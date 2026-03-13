from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

embedding = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

vector_db = Chroma(
    persist_directory="vector_db",
    embedding_function=embedding
)

def retrieve_context(query: str):

    results = vector_db.similarity_search(query, k=3)

    context = ""

    for doc in results:
        context += doc.page_content + "\n\n"

    return context