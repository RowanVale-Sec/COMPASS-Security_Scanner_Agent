"""
Azure OpenAI implementation of the LLMProvider interface.

Uses `AzureOpenAIChatClient` (Microsoft Agent Framework) for agent/tool-use
calls and `openai.AsyncAzureOpenAI` for direct chat and structured JSON
completions. Behavior is intentionally byte-compatible with the pre-migration
code path so that Azure users see no regression.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Sequence

from shared.llm_provider import (
    AgentRunResult,
    EmbeddingsProvider,
    LLMAgent,
    LLMProvider,
    ProviderCredentials,
)


class AzureAgent(LLMAgent):
    """Wraps an agent built from `AzureOpenAIChatClient.create_agent` so it
    conforms to the provider-agnostic `LLMAgent` interface."""

    def __init__(self, framework_agent: Any):
        self._agent = framework_agent

    async def run(self, prompt: str) -> AgentRunResult:
        result = await self._agent.run(prompt)
        text = result.text if hasattr(result, "text") else str(result)
        return AgentRunResult(text=text)


class AzureProvider(LLMProvider):
    """LLMProvider backed by Azure OpenAI via Microsoft Agent Framework for
    agent calls and the `openai.AsyncAzureOpenAI` client for direct calls."""

    def __init__(self, creds: ProviderCredentials):
        if creds.provider != "azure":
            raise ValueError(f"AzureProvider requires azure credentials, got {creds.provider}")
        self._creds = creds
        self._chat_client = None
        self._async_client = None

    def _get_chat_client(self):
        if self._chat_client is None:
            from agent_framework.azure import AzureOpenAIChatClient
            self._chat_client = AzureOpenAIChatClient(
                endpoint=self._creds.endpoint,
                api_key=self._creds.api_key,
                model=self._creds.deployment,
            )
        return self._chat_client

    def _get_async_client(self):
        if self._async_client is None:
            from openai import AsyncAzureOpenAI
            self._async_client = AsyncAzureOpenAI(
                api_key=self._creds.api_key,
                azure_endpoint=self._creds.endpoint,
                api_version=self._creds.api_version or "2024-08-01-preview",
            )
        return self._async_client

    def create_agent(
        self,
        instructions: str,
        tools: Optional[Sequence[Callable[..., Any]]] = None,
        name: Optional[str] = None,
    ) -> LLMAgent:
        kwargs: Dict[str, Any] = {"instructions": instructions, "tools": list(tools or [])}
        if name is not None:
            kwargs["name"] = name
        framework_agent = self._get_chat_client().create_agent(**kwargs)
        return AzureAgent(framework_agent)

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 800,
        system: Optional[str] = None,
    ) -> str:
        client = self._get_async_client()
        msgs: List[Dict[str, str]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)

        response = await client.chat.completions.create(
            model=self._creds.deployment,
            messages=msgs,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content or ""

    async def structured_output(
        self,
        schema: Dict[str, Any],
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 800,
    ) -> Dict[str, Any]:
        client = self._get_async_client()
        msgs: List[Dict[str, str]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})

        response = await client.chat.completions.create(
            model=self._creds.deployment,
            messages=msgs,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        content = (response.choices[0].message.content or "").strip()
        parsed = json.loads(content)

        # Best-effort schema validation. Fail loudly to catch drift.
        try:
            import jsonschema
            jsonschema.validate(instance=parsed, schema=schema)
        except ImportError:
            pass  # jsonschema is optional; skip validation if not installed
        return parsed
