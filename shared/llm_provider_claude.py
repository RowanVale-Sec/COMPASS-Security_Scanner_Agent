"""
Claude (Anthropic) implementation of the LLMProvider interface.

Uses the `anthropic` Python SDK directly. Implements a self-managed tool-use
loop that:
  - Converts Python functions (with `Annotated[T, Field(description=...)]`
    parameters used across the codebase) into Claude tool schemas.
  - Calls `messages.create`, handles `tool_use` stop reasons by invoking the
    matching Python function and feeding `tool_result` blocks back until the
    model responds with `end_turn`.

Default model: `claude-sonnet-4-5` (best tool-use/coding model; Opus is too
slow and costly for long chains; Haiku struggles with multi-step reasoning
in threat modeling).
"""

from __future__ import annotations

import inspect
import json
import typing
from dataclasses import is_dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, get_args, get_origin

from shared.llm_provider import (
    AgentRunResult,
    LLMAgent,
    LLMProvider,
    ProviderCredentials,
)


DEFAULT_MAX_ITERATIONS = 25


def _supports_temperature(model: str) -> bool:
    """Anthropic deprecated the `temperature` parameter on Opus 4.5+ (including
    4.6 and 4.7). Passing it to those models returns a 400 error. Sonnet and
    Haiku families still accept it.
    """
    return not model.startswith("claude-opus-4-")


def _json_type_for(py_type: Any) -> Dict[str, Any]:
    """Map a Python type hint to a minimal JSON Schema fragment."""
    origin = get_origin(py_type)

    if py_type is str:
        return {"type": "string"}
    if py_type is int:
        return {"type": "integer"}
    if py_type is float:
        return {"type": "number"}
    if py_type is bool:
        return {"type": "boolean"}

    if origin in (list, List) or py_type is list:
        args = get_args(py_type)
        item_schema = _json_type_for(args[0]) if args else {}
        return {"type": "array", "items": item_schema}
    if origin in (dict, Dict) or py_type is dict:
        return {"type": "object"}
    if origin is typing.Union:
        non_none = [a for a in get_args(py_type) if a is not type(None)]
        if len(non_none) == 1:
            return _json_type_for(non_none[0])
        return {"type": "string"}

    return {"type": "string"}


def _extract_field_description(metadata: tuple) -> Optional[str]:
    """Given the extra metadata on an Annotated[...], pull a description out
    of a Pydantic `Field(...)` instance if one is present."""
    for meta in metadata:
        desc = getattr(meta, "description", None)
        if isinstance(desc, str) and desc:
            return desc
        if isinstance(meta, dict) and "description" in meta:
            return str(meta["description"])
    return None


def python_fn_to_claude_tool(fn: Callable[..., Any]) -> Dict[str, Any]:
    """Convert a Python function signature into a Claude tool schema."""
    sig = inspect.signature(fn)
    hints = typing.get_type_hints(fn, include_extras=True)

    properties: Dict[str, Any] = {}
    required: List[str] = []

    for param_name, param in sig.parameters.items():
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue

        hint = hints.get(param_name, str)
        if get_origin(hint) is typing.Annotated:
            args = get_args(hint)
            base_type = args[0]
            description = _extract_field_description(args[1:])
        else:
            base_type = hint
            description = None

        schema = _json_type_for(base_type)
        if description:
            schema["description"] = description
        properties[param_name] = schema

        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    return {
        "name": fn.__name__,
        "description": (fn.__doc__ or "").strip() or fn.__name__,
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
    }


def _serialize_tool_result(value: Any) -> str:
    """Coerce tool return values to a string Claude can consume."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except TypeError:
        return str(value)


def _extract_text(content: Any) -> str:
    """Pull the concatenated text from Claude response content blocks."""
    parts: List[str] = []
    for block in content or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", ""))
    return "\n".join(p for p in parts if p)


class ClaudeAgent(LLMAgent):
    """Agent that drives the Anthropic tool-use loop."""

    def __init__(
        self,
        client: Any,
        model: str,
        instructions: str,
        tools: Sequence[Callable[..., Any]],
        max_tokens: int,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
    ):
        self._client = client
        self._model = model
        self._instructions = instructions
        self._max_tokens = max_tokens
        self._max_iterations = max_iterations
        self._tool_map = {fn.__name__: fn for fn in tools}
        self._tool_schemas = [python_fn_to_claude_tool(fn) for fn in tools]

    async def run(self, prompt: str) -> AgentRunResult:
        messages: List[Dict[str, Any]] = [{"role": "user", "content": prompt}]

        for _ in range(self._max_iterations):
            kwargs: Dict[str, Any] = {
                "model": self._model,
                "max_tokens": self._max_tokens,
                "system": self._instructions,
                "messages": messages,
            }
            if self._tool_schemas:
                kwargs["tools"] = self._tool_schemas

            response = await self._client.messages.create(**kwargs)

            messages.append({"role": "assistant", "content": response.content})

            stop_reason = getattr(response, "stop_reason", None)

            if stop_reason in ("end_turn", "stop_sequence"):
                return AgentRunResult(text=_extract_text(response.content))

            if stop_reason == "max_tokens":
                raise RuntimeError(
                    "Claude response truncated (stop_reason=max_tokens); "
                    "increase CLAUDE_MAX_TOKENS"
                )

            if stop_reason == "tool_use":
                tool_results = await self._invoke_tools(response.content)
                messages.append({"role": "user", "content": tool_results})
                continue

            return AgentRunResult(text=_extract_text(response.content))

        raise RuntimeError(
            f"Claude agent exceeded max_iterations={self._max_iterations} without end_turn"
        )

    async def _invoke_tools(self, content: Any) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for block in content or []:
            if getattr(block, "type", None) != "tool_use":
                continue

            tool_name = block.name
            tool_id = block.id
            tool_input = block.input or {}

            fn = self._tool_map.get(tool_name)
            if fn is None:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": f"ERROR: unknown tool {tool_name!r}",
                    "is_error": True,
                })
                continue

            try:
                out = fn(**tool_input)
                if inspect.iscoroutine(out):
                    out = await out
                results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": _serialize_tool_result(out),
                })
            except Exception as exc:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": f"ERROR: {type(exc).__name__}: {exc}",
                    "is_error": True,
                })
        return results


class ClaudeProvider(LLMProvider):
    """LLMProvider backed by Anthropic's Claude API."""

    def __init__(self, creds: ProviderCredentials):
        if creds.provider != "claude":
            raise ValueError(f"ClaudeProvider requires claude credentials, got {creds.provider}")
        if not creds.model:
            raise ValueError("ClaudeProvider requires a model name")
        self._creds = creds
        self._client = None

    def _get_client(self):
        if self._client is None:
            from anthropic import AsyncAnthropic
            self._client = AsyncAnthropic(api_key=self._creds.api_key)
        return self._client

    def create_agent(
        self,
        instructions: str,
        tools: Optional[Sequence[Callable[..., Any]]] = None,
        name: Optional[str] = None,
    ) -> LLMAgent:
        return ClaudeAgent(
            client=self._get_client(),
            model=self._creds.model,
            instructions=instructions,
            tools=list(tools or []),
            max_tokens=self._creds.max_tokens,
        )

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 800,
        system: Optional[str] = None,
    ) -> str:
        client = self._get_client()
        kwargs: Dict[str, Any] = {
            "model": self._creds.model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if _supports_temperature(self._creds.model):
            kwargs["temperature"] = temperature
        if system:
            kwargs["system"] = system

        response = await client.messages.create(**kwargs)
        return _extract_text(response.content)

    async def structured_output(
        self,
        schema: Dict[str, Any],
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 800,
    ) -> Dict[str, Any]:
        """Force a single tool call whose input_schema matches `schema`.

        Claude will emit exactly one tool_use block whose `input` satisfies
        the schema; we return it directly.
        """
        client = self._get_client()
        tool = {
            "name": "return_result",
            "description": "Return the structured result.",
            "input_schema": schema,
        }
        kwargs: Dict[str, Any] = {
            "model": self._creds.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [tool],
            "tool_choice": {"type": "tool", "name": "return_result"},
        }
        if _supports_temperature(self._creds.model):
            kwargs["temperature"] = temperature
        if system:
            kwargs["system"] = system

        response = await client.messages.create(**kwargs)
        for block in response.content or []:
            if getattr(block, "type", None) == "tool_use" and block.name == "return_result":
                return dict(block.input)

        raise RuntimeError(
            "Claude did not return a structured tool_use block for return_result"
        )
