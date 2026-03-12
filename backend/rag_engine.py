from langchain.vectorstores import Chroma
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.schema import Document

embedding = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

documents = [
    Document(
        page_content="Privilege escalation using sudo commands",
        metadata={"technique": "T1068"}
    ),
    Document(
        page_content="Command execution via scripts or binaries",
        metadata={"technique": "T1059"}
    ),
    Document(
        page_content="Outbound communication with command and control servers",
        metadata={"technique": "T1071"}
    )
]

vector_db = Chroma.from_documents(documents, embedding)


def retrieve_context(query: str):
    docs = vector_db.similarity_search(query, k=2)
    return docs