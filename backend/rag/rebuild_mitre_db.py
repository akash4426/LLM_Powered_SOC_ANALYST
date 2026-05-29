"""
rebuild_mitre_db.py
-------------------
Rebuilds the ChromaDB vector database from MITRE ATT&CK data with:
  1. chromadb native API (no langchain bridge — avoids version conflicts)
  2. Every chunk prefixed with its Technique ID + Name (so split chunks are 
     still identifiable and retrievable by T-ID keyword search)
  3. Larger chunk size (800 chars) with meaningful overlap (100 chars)
  4. Synonym injection — adds common attack tool names to technique documents
     so queries like "mimikatz" find T1003 even if the word isn't in the text
  5. Metadata stored per chunk for filtering
"""

import json
import os
import re
import sys
import time

# ── Config ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MITRE_JSON   = os.path.join(PROJECT_ROOT, "data", "enterprise-attack.json")
VECTOR_DB    = os.path.join(PROJECT_ROOT, "vector_db")
EMBED_MODEL  = "all-MiniLM-L6-v2"
CHUNK_SIZE   = 800
CHUNK_OVERLAP = 120
BATCH_SIZE   = 200

# ── Tool / synonym injection ──────────────────────────────────────────────────
# Maps technique IDs to extra keywords that analysts use but MITRE text may not.
TECHNIQUE_SYNONYMS = {
    "T1003": "mimikatz lsass dump hashdump secretsdump credential dumping ntds",
    "T1059": "command execution powershell.exe cmd.exe wscript cscript bash python malicious script run execute launch T1059.001 T1059.003 scripting interpreter",
    "T1110": "brute force password spray hydra medusa credential stuffing failed login",
    "T1021": "psexec lateral movement smb rdp wmi remote execution",
    "T1562": "shadow copy deletion vssadmin delete shadows bcdedit recoveryenabled disable antivirus av taskkill defender wevtutil clear-eventlog impair defenses security tools",
    "T1490": "inhibit system recovery backup deletion ransomware recovery prevention",
    "T1071": "c2 beacon command and control http https dns covert channel",
    "T1041": "exfiltration data theft upload large transfer outbound",
    "T1566": "phishing email attachment spear phish malicious link",
    "T1486": "ransomware encryption locked files ransom note",
    "T1548": "uac bypass privilege escalation sudo runas token impersonation",
    "T1018": "nmap port scan host discovery enumeration network scan",
    "T1074": "data staging archive compression 7zip rar staging",
    "T1070": "log clearing event log delete indicator removal",
    "T1078": "valid accounts stolen credentials account takeover",
    "T1027": "obfuscated files encoded payload base64 packed",
    "T1047": "wmi wmic windows management instrumentation",
    "T1053": "scheduled task cron job persistence startup",
    "T1082": "system information discovery whoami systeminfo hostname",
    "T1083": "file directory discovery ls dir find enumerate files",
}


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP):
    """Split text into overlapping chunks, preserving word boundaries."""
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        # extend to next word boundary
        if end < len(text):
            last_space = text.rfind(' ', start, end)
            if last_space > start:
                end = last_space
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break
        start = end - overlap
    return [c for c in chunks if len(c.strip()) > 30]


def build_documents():
    """Parse MITRE ATT&CK JSON and return list of (id, content, metadata) tuples."""
    with open(MITRE_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = []
    technique_count = 0

    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue

        name        = obj.get("name", "")
        description = obj.get("description", "")
        if not description:
            continue

        # Extract technique ID
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue

        # Extract tactics
        tactics = [
            ph.get("phase_name", "")
            for ph in obj.get("kill_chain_phases", [])
            if ph.get("kill_chain_name") == "mitre-attack"
        ]

        # Clean description — remove markdown links but keep text
        clean_desc = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)
        clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()

        # Build the full technique document with header repeated for each chunk
        header = (
            f"Technique ID: {technique_id}\n"
            f"Technique Name: {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
        )

        # Add synonyms if available
        base_id = technique_id.split(".")[0]
        synonyms = TECHNIQUE_SYNONYMS.get(technique_id, TECHNIQUE_SYNONYMS.get(base_id, ""))
        if synonyms:
            synonym_line = f"Also known as / related tools: {synonyms}\n"
        else:
            synonym_line = ""

        full_text = header + synonym_line + f"Description: {clean_desc}"

        # Split into chunks; each chunk gets the header prepended
        raw_chunks = chunk_text(clean_desc, CHUNK_SIZE, CHUNK_OVERLAP)
        for i, chunk in enumerate(raw_chunks):
            # Prepend header to EVERY chunk so the technique ID is always present
            if i == 0:
                chunk_text_final = header + synonym_line + "Description: " + chunk
            else:
                chunk_text_final = (
                    f"[Continued] Technique ID: {technique_id}\n"
                    f"Technique Name: {name}\n"
                    + ("Related: " + synonyms + "\n" if synonyms else "")
                    + chunk
                )

            doc_id = f"{technique_id}_chunk{i}"
            meta = {
                "technique_id": technique_id,
                "name": name,
                "tactics": ", ".join(tactics),
                "chunk_index": i,
            }
            docs.append((doc_id, chunk_text_final, meta))

        technique_count += 1

    print(f"Techniques loaded: {technique_count}")
    print(f"Total chunks:      {len(docs)}")
    return docs


def rebuild():
    import chromadb
    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

    docs = build_documents()

    # ── Delete and recreate the collection ───────────────────────────────────
    print(f"\nConnecting to ChromaDB at: {VECTOR_DB}")
    client = chromadb.PersistentClient(path=VECTOR_DB)

    COLLECTION_NAME = "mitre_attack"

    # Delete old collections
    existing = [c.name for c in client.list_collections()]
    for name in existing:
        print(f"Deleting old collection: {name}")
        client.delete_collection(name)

    ef = SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},  # cosine similarity
    )

    # ── Batch upsert ──────────────────────────────────────────────────────────
    total = len(docs)
    print(f"\nInserting {total} chunks in batches of {BATCH_SIZE}…")
    t0 = time.time()

    for batch_start in range(0, total, BATCH_SIZE):
        batch = docs[batch_start:batch_start + BATCH_SIZE]
        ids       = [d[0] for d in batch]
        documents = [d[1] for d in batch]
        metadatas = [d[2] for d in batch]

        collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        pct = min(100, int(100 * (batch_start + len(batch)) / total))
        elapsed = time.time() - t0
        print(f"  {batch_start + len(batch)}/{total} ({pct}%)  {elapsed:.1f}s")

    # ── Verify ────────────────────────────────────────────────────────────────
    final_count = collection.count()
    print(f"\nDone! Collection '{COLLECTION_NAME}' has {final_count} chunks.")
    print(f"Total time: {time.time() - t0:.1f}s")

    # Quick smoke test
    print("\nSmoke test queries:")
    tests = [
        ("mimikatz LSASS credential dumping", "T1003"),
        ("ssh brute force failed password spray", "T1110"),
        ("shadow copy delete vssadmin defense evasion", "T1562"),
        ("lateral movement SMB pass the hash psexec", "T1021"),
        ("powershell obfuscation iex invoke-expression", "T1059"),
    ]
    hits = 0
    for query, expected in tests:
        res = collection.query(query_texts=[query], n_results=3, include=["metadatas", "distances"])
        top_meta = res["metadatas"][0][0] if res["metadatas"][0] else {}
        top_tid  = top_meta.get("technique_id", "?")
        dist     = res["distances"][0][0] if res["distances"][0] else 999
        matched  = expected.split(".")[0] in top_tid
        hits += matched
        print(f"  [{'OK' if matched else 'MISS'}] dist={dist:.4f}  expected={expected}  got={top_tid}")
    print(f"\nAccuracy: {hits}/{len(tests)} = {100*hits//len(tests)}%")


if __name__ == "__main__":
    rebuild()
