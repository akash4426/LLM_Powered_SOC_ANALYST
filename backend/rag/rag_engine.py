"""
rag_engine.py
-------------
MITRE ATT&CK semantic retrieval engine.

Uses the chromadb native Python API directly — this avoids the
langchain-core/langchain-chroma version incompatibility that caused silent
fallback to (broken) SQLite FTS on every query.

Retrieval strategy:
  1. Cosine-similarity vector search via chromadb's native .query()
  2. Over-fetch (k*3 candidates) then apply Maximal Marginal Relevance (MMR)
     manually so returned snippets are both relevant AND diverse.
  3. SQLite FTS fallback only if chromadb itself is unavailable.
  4. Distance threshold: skips chunks with cosine distance > 0.85 (low rel.)
"""

import os
import re
import sqlite3
from typing import Any, List, Optional, Tuple

from dotenv import load_dotenv
load_dotenv()

# ── Globals (lazy init) ───────────────────────────────────────────────────────
_chroma_client:     Optional[Any] = None
_chroma_collection: Optional[Any] = None

# ── Constants ─────────────────────────────────────────────────────────────────
COLLECTION_NAME     = "mitre_attack"
EMBED_MODEL         = "all-MiniLM-L6-v2"
MAX_DISTANCE        = 0.85   # cosine distance threshold — drop irrelevant results
MMR_LAMBDA          = 0.65   # relevance weight in MMR (1.0 = pure relevance)
DEFAULT_K           = 5


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _resolve_persist_directory() -> str:
    raw_dir = (os.getenv("RAG_VECTOR_DB_DIR") or "vector_db").strip()
    base    = _project_root()
    candidate = raw_dir if os.path.isabs(raw_dir) else os.path.join(base, raw_dir)
    if not os.path.exists(candidate):
        fallback = os.path.join(base, "vector_db")
        if os.path.exists(fallback):
            return fallback
    return candidate


def _sqlite_db_path() -> str:
    return os.path.join(_resolve_persist_directory(), "chroma.sqlite3")


# ── Native chromadb helpers ───────────────────────────────────────────────────

def _get_collection() -> Any:
    """Lazily initialise the chromadb client and return the MITRE collection."""
    global _chroma_client, _chroma_collection

    if _chroma_collection is not None:
        return _chroma_collection

    import chromadb
    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

    persist_dir = _resolve_persist_directory()
    model_name  = os.getenv("RAG_EMBEDDING_MODEL", EMBED_MODEL)

    _chroma_client = chromadb.PersistentClient(path=persist_dir)
    ef = SentenceTransformerEmbeddingFunction(model_name=model_name)

    # Try the new collection name first; fall back to the legacy 'langchain' name
    existing_names = [c.name for c in _chroma_client.list_collections()]
    if COLLECTION_NAME in existing_names:
        col_name = COLLECTION_NAME
    elif existing_names:
        col_name = existing_names[0]
    else:
        raise RuntimeError("No collections found in vector_db — run rebuild_mitre_db.py first")

    _chroma_collection = _chroma_client.get_collection(
        name=col_name, embedding_function=ef
    )
    return _chroma_collection


# ── MMR implementation ────────────────────────────────────────────────────────

def _cosine_sim(a: List[float], b: List[float]) -> float:
    """Simple cosine similarity between two equal-length vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    na  = sum(x * x for x in a) ** 0.5
    nb  = sum(x * x for x in b) ** 0.5
    return dot / (na * nb + 1e-9)


def _mmr_rerank(
    candidates: List[Tuple[str, List[float], float]],   # (doc, embedding, distance)
    k: int,
    lam: float = MMR_LAMBDA,
) -> List[str]:
    """
    Maximal Marginal Relevance re-ranking.
    Returns up to k documents that are relevant AND mutually diverse.
    candidates: list of (doc_text, embedding_vector, cosine_distance)
    """
    if not candidates:
        return []

    selected_texts:  List[str]       = []
    selected_embeds: List[List[float]] = []
    remaining = list(candidates)

    while len(selected_texts) < k and remaining:
        best_idx  = -1
        best_score = -1e9

        for i, (doc, emb, dist) in enumerate(remaining):
            # Relevance: invert cosine distance → similarity
            relevance = 1.0 - dist

            # Redundancy: max similarity to already-selected docs
            if selected_embeds:
                redundancy = max(_cosine_sim(emb, se) for se in selected_embeds)
            else:
                redundancy = 0.0

            score = lam * relevance - (1 - lam) * redundancy
            if score > best_score:
                best_score = score
                best_idx   = i

        if best_idx < 0:
            break

        doc, emb, _ = remaining.pop(best_idx)
        selected_texts.append(doc)
        selected_embeds.append(emb)

    return selected_texts


def _deduplicate_snippets(snippets: List[str]) -> List[str]:
    """Remove near-duplicate snippets (same first 80 chars)."""
    seen:   set = set()
    result: List[str] = []
    for s in snippets:
        key = re.sub(r'\s+', ' ', s.strip())[:80]
        if key not in seen:
            seen.add(key)
            result.append(s.strip())
    return result


# ── SQLite FTS fallback ───────────────────────────────────────────────────────

def _build_fts_query(query: str) -> str:
    stopwords = {
        "the", "and", "or", "of", "in", "to", "a", "is", "for", "via",
        "over", "with", "by", "on", "an", "at", "from", "that", "this",
    }
    t_ids    = re.findall(r"T\d{4}(?:\.\d{3})?", query)
    tokens   = re.findall(r"[A-Za-z0-9_-]+", query)
    keywords = [t for t in tokens if len(t) > 3 and t.lower() not in stopwords]
    all_tok  = list(dict.fromkeys(t_ids + keywords))[:16]
    return " OR ".join(all_tok) if all_tok else ""


def _retrieve_context_sqlite(query: str, k: int = DEFAULT_K) -> str:
    db_path = _sqlite_db_path()
    if not os.path.exists(db_path):
        return ""

    fts_query = _build_fts_query(query)
    if not fts_query:
        return ""

    try:
        con  = sqlite3.connect(db_path)
        cur  = con.cursor()
        rows = cur.execute(
            "SELECT string_value FROM embedding_fulltext_search "
            "WHERE embedding_fulltext_search MATCH ? LIMIT ?",
            (fts_query, k * 2),
        ).fetchall()
        con.close()
    except Exception:
        return ""

    snippets = _deduplicate_snippets([r[0] for r in rows if r and r[0]])
    return "\n\n".join(snippets[:k])


# ── Public API ────────────────────────────────────────────────────────────────

def retrieve_context(query: str, k: int = DEFAULT_K) -> str:
    """
    Retrieve top-k relevant MITRE ATT&CK passages for the given query.

    Strategy:
      1. Use chromadb native API with SentenceTransformer embeddings.
      2. Over-fetch k*3 candidates, filter by distance threshold.
      3. MMR re-rank for relevance + diversity.
      4. Fall back to SQLite FTS if chromadb is unavailable.

    Args:
        query: Enriched semantic query (from get_mitre_query in event_extractor).
        k:     Number of passages to return.
    """
    cleaned = (query or "").strip()
    if not cleaned:
        return ""

    k = max(1, int(k))

    try:
        collection = _get_collection()
        fetch_k    = min(k * 3, 30)   # over-fetch for MMR

        results = collection.query(
            query_texts=[cleaned],
            n_results=fetch_k,
            include=["documents", "embeddings", "distances"],
        )

        documents  = results.get("documents",  [[]])[0]
        embeddings = results.get("embeddings", [[]])[0]
        distances  = results.get("distances",  [[]])[0]

        # Filter by distance threshold (drop low-relevance chunks)
        candidates = [
            (doc, emb, dist)
            for doc, emb, dist in zip(documents, embeddings, distances)
            if doc and dist <= MAX_DISTANCE
        ]

        if not candidates:
            # Relax threshold if nothing passes (rare edge case)
            candidates = [
                (doc, emb, dist)
                for doc, emb, dist in zip(documents, embeddings, distances)
                if doc
            ][:k]

        # MMR re-rank
        selected = _mmr_rerank(candidates, k=k, lam=MMR_LAMBDA)
        selected = _deduplicate_snippets(selected)
        context  = "\n\n".join(selected[:k])

        if context.strip():
            return context

    except Exception as exc:
        # Log to stderr so backend logs show the issue without crashing
        import sys
        print(f"[rag_engine] vector search failed: {exc}", file=sys.stderr)

    # Guaranteed fallback
    return _retrieve_context_sqlite(cleaned, k=k)