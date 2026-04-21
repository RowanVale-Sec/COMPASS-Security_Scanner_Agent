"""
COMPASS LLM Provider Abstraction.

Provides a provider-agnostic interface for chat completions, agent creation with
tools, structured JSON output, and text embeddings. Concrete implementations
(Azure OpenAI, Claude) live in `shared.providers.*`.

Credentials are passed per-call via `ProviderCredentials` so that a future
frontend layer can supply request-scoped tokens without touching call sites.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence


ProviderName = Literal["azure", "claude"]


@dataclass(frozen=True)
class ProviderCredentials:
    """Credentials + model config for a single LLM provider invocation.

    Designed to be built either from environment (via `from_env`) or from an
    HTTP request (future use in the frontend redesign). All provider-specific
    fields are optional at the dataclass level; `from_env` enforces the
    requirements for the selected provider.
    """

    provider: ProviderName
    api_key: str

    # Azure-only fields
    endpoint: Optional[str] = None
    deployment: Optional[str] = None
    embedding_deployment: Optional[str] = None
    api_version: Optional[str] = None

    # Claude-only fields
    model: Optional[str] = None
    max_tokens: int = 4096

    @classmethod
    def from_env(cls, provider: Optional[str] = None) -> "ProviderCredentials":
        """Build credentials from environment variables.

        Provider selection order:
          1. explicit `provider` argument
          2. `LLM_PROVIDER` env var
          3. default to "azure"
        """
        provider = (provider or os.environ.get("LLM_PROVIDER", "azure")).lower()

        if provider == "azure":
            api_key = os.environ.get("AZURE_OPENAI_API_KEY")
            endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
            deployment = (
                os.environ.get("AZURE_OPENAI_CHAT_DEPLOYMENT_NAME")
                or os.environ.get("AZURE_OPENAI_DEPLOYMENT")
            )
            if not api_key or not endpoint or not deployment:
                raise ValueError(
                    "Azure provider requires AZURE_OPENAI_API_KEY, "
                    "AZURE_OPENAI_ENDPOINT, and AZURE_OPENAI_CHAT_DEPLOYMENT_NAME "
                    "(or AZURE_OPENAI_DEPLOYMENT)"
                )
            return cls(
                provider="azure",
                api_key=api_key,
                endpoint=endpoint,
                deployment=deployment,
                embedding_deployment=(
                    os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT")
                    or os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME")
                ),
                api_version=os.environ.get(
                    "AZURE_OPENAI_API_VERSION", "2024-08-01-preview"
                ),
            )

        if provider == "claude":
            api_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get(
                "ANTHROPIC_API_KEY"
            )
            if not api_key:
                raise ValueError(
                    "Claude provider requires CLAUDE_API_KEY (or ANTHROPIC_API_KEY)"
                )
            return cls(
                provider="claude",
                api_key=api_key,
                model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-5"),
                max_tokens=int(os.environ.get("CLAUDE_MAX_TOKENS", "4096")),
            )

        raise ValueError(f"Unknown LLM_PROVIDER: {provider!r} (expected 'azure' or 'claude')")


@dataclass
class AgentRunResult:
    """Result of running an LLM agent. Exposes `.text` to match existing call
    sites that access `result.text` on the Microsoft agent_framework result."""

    text: str


class LLMAgent(ABC):
    """A single-turn (internally multi-step) agent with tool-use capability."""

    @abstractmethod
    async def run(self, prompt: str) -> AgentRunResult:
        """Run the agent against `prompt`, internally invoking tools as needed,
        and return the final assistant text."""


class LLMProvider(ABC):
    """Provider-agnostic interface for chat and agent operations."""

    @abstractmethod
    def create_agent(
        self,
        instructions: str,
        tools: Optional[Sequence[Callable[..., Any]]] = None,
        name: Optional[str] = None,
    ) -> LLMAgent:
        """Create an agent with a system prompt and a set of Python-function
        tools. Tools must use `Annotated[T, Field(description=...)]` parameter
        annotations (same pattern used by the existing Azure-backed code)."""

    @abstractmethod
    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 800,
        system: Optional[str] = None,
    ) -> str:
        """Plain chat completion. Returns the assistant text only."""

    @abstractmethod
    async def structured_output(
        self,
        schema: Dict[str, Any],
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 800,
    ) -> Dict[str, Any]:
        """Return a dict that conforms to `schema` (JSON Schema). Providers may
        implement this via response_format=json_object (Azure) or forced
        tool-use (Claude)."""


class EmbeddingsProvider(ABC):
    """Text embeddings. Kept separate from LLMProvider because Claude has no
    embeddings endpoint and because the dedup pipeline's only LLM use here is
    semantic similarity."""

    @abstractmethod
    def embed(self, texts: List[str]) -> List[List[float]]:
        """Return a vector per input text. Implementations may batch."""

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Dimensionality of the embedding space."""


def get_provider(creds: Optional[ProviderCredentials] = None) -> LLMProvider:
    """Factory. Returns the provider implementation matching `creds.provider`.

    If `creds` is None, reads from environment.
    """
    if creds is None:
        creds = ProviderCredentials.from_env()

    if creds.provider == "azure":
        from shared.llm_provider_azure import AzureProvider
        return AzureProvider(creds)

    if creds.provider == "claude":
        from shared.llm_provider_claude import ClaudeProvider
        return ClaudeProvider(creds)

    raise ValueError(f"Unsupported provider: {creds.provider!r}")


def get_embeddings_provider() -> EmbeddingsProvider:
    """Factory for the embeddings provider. Currently returns a local
    sentence-transformers model; kept behind an interface for later swap."""
    from shared.llm_provider_local_embeddings import LocalEmbeddingsProvider
    return LocalEmbeddingsProvider()
