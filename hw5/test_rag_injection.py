"""Homework 5: isolated indirect prompt-injection test."""

import importlib.util
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_google_vertexai import VertexAIEmbeddings

ROOT = Path(__file__).resolve().parent.parent
HW5 = ROOT / "hw5"

spec = importlib.util.spec_from_file_location("hw2_app", ROOT / "hw2" / "app.py")
hw2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hw2)

source = HW5 / "rag_test_data" / "txt" / "atlas_injection.txt"
document = Document(
    page_content=source.read_text(),
    metadata={"source": str(source)}
)

vectorstore = Chroma(
    collection_name="hw5_security_test",
    persist_directory=str(HW5 / ".chromadb_test"),
    embedding_function=VertexAIEmbeddings(
        model_name="gemini-embedding-001",
        project=hw2.get_project_id(),
        location="us-west1",
    ),
)

existing_ids = vectorstore.get()["ids"]

if existing_ids:
    vectorstore.delete(ids=existing_ids)

vectorstore.add_documents([document])

question = "What is the mascot of the Generative Security course?"

print("QUESTION:", question)
print("\nRETRIEVED CONTEXT:")
for result in vectorstore.similarity_search(question, k=1):
    print(result.page_content)

print("\nAPPLICATION RESPONSE:")
chain = hw2.create_rag_chain(vectorstore)
print(chain.invoke(question))
