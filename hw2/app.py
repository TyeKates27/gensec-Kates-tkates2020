"""Baseline LangChain RAG application for Homework 2.

This file is intentionally simple and follows the core architecture from the
course examples in 02_LangChain/07_RAG:
- 09_rag_query.py for the retrieval + prompt + LLM chain
- 07_rag_loaddb.py for the vector store setup and document indexing flow

It keeps the app focused on the standard RAG pattern without adding any custom
Homework 2 feature yet.
"""

from __future__ import annotations

import os
from pathlib import Path

from langchain_chroma import Chroma
from langchain_community.document_loaders import CSVLoader, DirectoryLoader, TextLoader, UnstructuredMarkdownLoader
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_vertexai import VertexAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter


def get_project_id() -> str:
    """Return the GCP project ID from the environment.

    The course examples use Vertex AI embeddings, which require a Google Cloud
    project instead of a hard-coded API key.
    """
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT_ID")
    if not project_id:
        raise RuntimeError(
            "Missing Google Cloud project configuration. Set GOOGLE_CLOUD_PROJECT "
            "or GCP_PROJECT_ID in your environment before running this app."
        )
    return project_id


def get_model_name() -> str:
    """Return the model configured for the current environment."""
    return os.getenv("GOOGLE_MODEL", "gemini-2.0-flash")


def get_persist_directory() -> Path:
    """Return the directory used for the persistent Chroma vector database."""
    project_root = Path(__file__).resolve().parent.parent
    return project_root / "02_LangChain" / "07_RAG" / "rag_data" / ".chromadb"


def get_course_data_directory() -> Path:
    """Return the course rag_data folder used as the source corpus."""
    project_root = Path(__file__).resolve().parent.parent
    return project_root / "02_LangChain" / "07_RAG" / "rag_data"


def load_course_documents() -> list:
    """Load a small set of local course documents for the baseline index.

    This mirrors the indexing logic from the course examples, but keeps the
    first version intentionally simple by using the bundled local .txt and .md
    files in the course RAG data folder.
    """
    data_dir = get_course_data_directory()
    docs = []

    txt_dir = data_dir / "txt"
    if txt_dir.exists():
        docs.extend(DirectoryLoader(str(txt_dir), glob="**/*.txt", loader_cls=TextLoader).load())

    md_dir = data_dir / "md"
    if md_dir.exists():
        docs.extend(
            DirectoryLoader(str(md_dir), glob="**/*.md", loader_cls=UnstructuredMarkdownLoader).load()
        )

    csv_dir = data_dir / "csv"
    if csv_dir.exists():
        docs.extend(DirectoryLoader(str(csv_dir), glob="**/*.csv", loader_cls=CSVLoader).load())

    return docs


def build_vectorstore() -> Chroma:
    """Create or reopen the persistent Chroma vector database."""
    persist_directory = str(get_persist_directory())

    vectorstore = Chroma(
        persist_directory=persist_directory,
        embedding_function=VertexAIEmbeddings(
            model_name="gemini-embedding-001",
            project=get_project_id(),
            location="us-west1",
        ),
    )

    # Keep the baseline simple: only index documents if the database is empty.
    if not vectorstore.get()["ids"]:
        docs = load_course_documents()
        if docs:
            splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
            chunks = splitter.split_documents(docs)
            vectorstore.add_documents(chunks)

    return vectorstore


def format_docs(docs) -> str:
    """Convert retrieved documents into the context string for the LLM prompt."""
    return "\n\n".join(doc.page_content for doc in docs)


def create_rag_chain(vectorstore: Chroma):
    """Build the retrieval-augmented generation chain used by the course examples."""
    retriever = vectorstore.as_retriever()

    prompt = ChatPromptTemplate.from_template(
        """You are an assistant for question-answering tasks.
Use the following pieces of retrieved context to answer the question.
If you don't know the answer, just say that you don't know.
Keep the answer concise and use three sentences maximum.

Question: {question}

Context: {context}

Answer:"""
    )

    llm = ChatGoogleGenerativeAI(model=get_model_name())

    rag_chain = (
        {"context": retriever | format_docs, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )

    return rag_chain


def print_indexed_sources(vectorstore: Chroma) -> None:
    """Print the source metadata currently stored in the vector database."""
    print("\nRAG database initialized. Available sources:")
    try:
        sources = sorted({meta["source"] for meta in vectorstore.get()["metadatas"] if "source" in meta})
    except Exception:
        sources = []

    if not sources:
        print("  No documents indexed yet.")
        return

    for source in sources:
        print(f"  - {source}")


def run_query_loop(rag_chain) -> None:
    """Run a simple interactive loop for asking questions against the RAG chain."""
    print("\nWelcome to the Homework 2 RAG app. Type a question and press Enter.")
    print("Enter a blank line to exit.\n")

    while True:
        user_input = input("Question> ").strip()
        if not user_input:
            print("Goodbye.")
            break

        answer = rag_chain.invoke(user_input)
        print(f"\nAnswer:\n{answer}\n")


def main() -> None:
    """Run the baseline RAG application."""
    vectorstore = build_vectorstore()
    rag_chain = create_rag_chain(vectorstore)
    print_indexed_sources(vectorstore)
    run_query_loop(rag_chain)


if __name__ == "__main__":
    main()
