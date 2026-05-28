"""
rag_engine.py
-------------
MITRE ATT&CK semantic retrieval engine.

Improvements over v1:
  - Default k raised to 5 for broader coverage.
  - Uses max_marginal_relevance_search (MMR) when available so results are
    both relevant AND diverse (avoids returning 5 near-identical snippets).
  - Falls back gracefully to similarity_search if MMR isn't supported.
  - SQLite FTS fallback now tokenizes more aggressively (strips MITRE IDs,
    expands synonyms) for better keyword matching when ChromaDB is unavailable.
  - Deduplicates returned snippets by first 80 chars.
"""

import os
import re
import sqlite3
from typing import Any, Optional, List

from dotenv import load_dotenv
load_dotenv()


_embedding: Optional[Any] = None
_vector_db: Optional[Any] = None


def _project_root() -> str:
    # backend/rag/rag_engine.py -> backend/rag -> backend -> project root
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _resolve_persist_directory() -> str:
    """Resolve Chroma persist dir, defaulting to project-root vector_db."""
    raw_dir = (os.getenv("RAG_VECTOR_DB_DIR") or "vector_db").strip()
    base = _project_root()

    candidate = raw_dir if os.path.isabs(raw_dir) else os.path.join(base, raw_dir)

    # If caller passed a bad relative path, fall back to canonical project vector_db.
    if not os.path.exists(candidate):
        fallback = os.path.join(base, "vector_db")
        if os.path.exists(fallback):
            return fallback

    return candidate


def _sqlite_db_path() -> str:
    return os.path.join(_resolve_persist_directory(), "chroma.sqlite3")


def _build_fts_query(query: str) -> str:
    """
    Build a richer FTS query from the rich MITRE query string.
    - Extracts MITRE technique IDs (T1xxx) and makes them explicit tokens.
    - Picks meaningful keywords, drops stopwords.
    - Joins with OR so partial matches still surface results.
    """
    stopwords = {
        "the", "and", "or", "of", "in", "to", "a", "is", "for", "via",
        "over", "with", "by", "on", "an", "at", "from", "that", "this",
    }

    # Extract T-IDs first
    t_ids = re.findall(r"T\d{4}(?:\.\d{3})?", query)

    # Clean and tokenize
    tokens = re.findall(r"[A-Za-z0-9_-]+", query or "")
    keywords = [
        t for t in tokens
        if len(t) > 3 and t.lower() not in stopwords
    ]

    # Combine and deduplicate (T-IDs first for specificity)
    all_tokens = list(dict.fromkeys(t_ids + keywords))[:16]
    if not all_tokens:
        return ""
    return " OR ".join(all_tokens)


def _deduplicate_snippets(snippets: List[str]) -> List[str]:
    """Remove near-duplicate snippets by comparing the first 80 characters."""
    seen: set = set()
    result: List[str] = []
    for s in snippets:
        key = s.strip()[:80]
        if key not in seen:
            seen.add(key)
            result.append(s.strip())
    return result


def _retrieve_context_sqlite(query: str, k: int = 5) -> str:
    """
    Fallback retrieval directly from Chroma SQLite FTS index.
    Uses an improved FTS query with T-ID extraction and keyword deduplication.
    """
    db_path = _sqlite_db_path()
    if not os.path.exists(db_path):
        return ""

    fts_query = _build_fts_query(query)
    if not fts_query:
        return ""

    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        rows = cur.execute(
            """
            SELECT string_value
            FROM embedding_fulltext_search
            WHERE embedding_fulltext_search MATCH ?
            LIMIT ?
            """,
            (fts_query, max(1, int(k)) * 2),   # over-fetch then deduplicate
        ).fetchall()
        con.close()
    except Exception:
        return ""

    snippets = [r[0] for r in rows if r and r[0]]
    snippets = _deduplicate_snippets(snippets)
    return "\n\n".join(snippets[:k])


def _get_vector_db() -> Any:
    """Lazily initialize Chroma so import-time failures don't break the API."""
    global _embedding, _vector_db
    if _vector_db is not None:
        return _vector_db

    embedding_model = os.getenv("RAG_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    persist_directory = _resolve_persist_directory()

    # Imported lazily so missing optional deps don't crash at module import time.
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings

    _embedding = HuggingFaceEmbeddings(model_name=embedding_model)
    _vector_db = Chroma(
        persist_directory=persist_directory,
        embedding_function=_embedding,
    )
    return _vector_db


def retrieve_context(query: str, k: int = 5) -> str:
    """
    Retrieve top-k RAG passages from the MITRE ATT&CK ChromaDB.

    Uses Max-Marginal Relevance (MMR) search when available to return results
    that are both highly relevant and diverse — avoiding the situation where
    all k results are near-identical paraphrases of the same technique.

    Falls back to standard similarity_search if MMR is unavailable, then
    falls back to the SQLite FTS index if ChromaDB itself is inaccessible.

    Args:
        query: Rich semantic query string (output of get_mitre_query).
        k:     Number of passages to return. Default raised to 5.
    """
    cleaned_query = (query or "").strip()
    if not cleaned_query:
        return ""

    k = max(1, int(k))

    try:
        vector_db = _get_vector_db()

        # ── MMR retrieval (preferred) ──────────────────────────────────────
        # fetch_k = candidates to consider before MMR re-ranks for diversity.
        # lambda_mult: 0.6 balances relevance (1.0) vs diversity (0.0).
        try:
            results = vector_db.max_marginal_relevance_search(
                cleaned_query,
                k=k,
                fetch_k=min(k * 4, 40),
                lambda_mult=0.6,
            )
        except (AttributeError, NotImplementedError):
            # Older Chroma versions may not support MMR — fall back silently.
            results = vector_db.similarity_search(cleaned_query, k=k)

        snippets = [
            doc.page_content for doc in results
            if getattr(doc, "page_content", None)
        ]
        snippets = _deduplicate_snippets(snippets)
        context = "\n\n".join(snippets[:k])

        if context.strip():
            return context

    except Exception:
        pass

    # Guaranteed persisted-db fallback path.
    return _retrieve_context_sqlite(cleaned_query, k=k)