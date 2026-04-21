"""
Local embeddings using sentence-transformers.

Uses `all-MiniLM-L6-v2` (384-dim, ~80MB). Model loads once per process via a
class-level lazy singleton, so the dedup loop avoids reload overhead.

Chosen over hosted APIs because Claude has no embeddings endpoint and we want
to keep embeddings decoupled from any specific LLM provider. Quality is ~90%
of text-embedding-3-small for short security findings; the existing agent
validation pass in the deduplicator compensates for edge-case drift.
"""

from __future__ import annotations

import os
import threading
from typing import List

from shared.llm_provider import EmbeddingsProvider


class LocalEmbeddingsProvider(EmbeddingsProvider):
    DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
    DEFAULT_DIM = 384

    _model = None
    _model_lock = threading.Lock()

    def __init__(self, model_name: str | None = None):
        self._model_name = model_name or os.environ.get(
            "EMBEDDINGS_MODEL", self.DEFAULT_MODEL
        )

    @classmethod
    def _get_model(cls, model_name: str):
        if cls._model is None:
            with cls._model_lock:
                if cls._model is None:
                    from sentence_transformers import SentenceTransformer
                    cls._model = SentenceTransformer(model_name)
        return cls._model

    def embed(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        model = self._get_model(self._model_name)
        vectors = model.encode(texts, normalize_embeddings=True)
        return [v.tolist() for v in vectors]

    @property
    def dimension(self) -> int:
        return self.DEFAULT_DIM
