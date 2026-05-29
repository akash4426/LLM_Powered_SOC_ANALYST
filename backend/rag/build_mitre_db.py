"""
build_mitre_db.py
-----------------
Alias — delegates to the improved rebuild_mitre_db.py.
Run this (or rebuild_mitre_db.py directly) to initialise/refresh the
MITRE ATT&CK ChromaDB vector store.

Usage:
    python backend/rag/build_mitre_db.py
"""
from rebuild_mitre_db import rebuild

if __name__ == "__main__":
    rebuild()