# Homework 2 RAG Application

This application is a simple retrieval-augmented generation (RAG) chat app built for Homework 2. It uses the same core workflow as the LangChain examples in `02_LangChain/07_RAG`, but adds a custom Homework 2 feature: support for PDF documents in addition to the course's text-based sources.

## Purpose

The app loads a local document corpus into a persistent Chroma vector database, retrieves the most relevant chunks for a question, and passes those chunks to a Gemini model to generate a grounded answer. The goal is to keep the implementation simple and consistent with the course examples while extending the corpus to include PDFs.

## Base implementation

The code is based on the course LangChain RAG examples in:

- `02_LangChain/07_RAG/07_rag_loaddb.py`
- `02_LangChain/07_RAG/09_rag_query.py`

The project preserves the same general architecture:

- persistent vector database
- embedding generation
- text splitting / chunking
- retriever creation
- prompt template
- LLM call with retrieved context
- output parsing

## Homework 2 custom feature

The app extends the original course examples by adding PDF support using the pre-built LangChain PDF loader:

- `PyPDFDirectoryLoader`

This loader is integrated into the same indexing pipeline used for the other supported file types, so PDFs are embedded and queried in the same way as the local text files.

## Supported document types

The current implementation supports the following local document types, if present in the source corpus:

- `.txt`
- `.md`
- `.csv`
- `.pdf`

The application prefers the local homework test corpus under `hw2/test_data`, and it falls back to the course RAG data directory if needed.

## High-level RAG workflow

At a high level, the app does the following:

1. Finds the local corpus folder.
2. Loads supported documents from the directory tree.
3. Splits documents into chunks using `RecursiveCharacterTextSplitter`.
4. Embeds the chunks using Vertex AI embeddings.
5. Stores the embeddings in a persistent Chroma database.
6. Creates a retriever from that vectorstore.
7. Builds a prompt that includes the retrieved document context and the user's question.
8. Sends the prompt to the configured Gemini model.
9. Returns the model answer based on the retrieved context.

## Required environment variables

Set the required environment variables before running the app. Do not hard-code credentials, tokens, project IDs, or other secrets in source files.

```bash
export GOOGLE_CLOUD_PROJECT="gensec-kates-tkates2020"
export GOOGLE_MODEL="gemini-3.6-flash"
```

The app also accepts this alternate project variable if needed:

```bash
export GCP_PROJECT_ID="gensec-kates-tkates2020"
```

You must also have valid Google Cloud local authentication configured, for example:

```bash
gcloud auth application-default login
```

## Install and run with uv

From the repository root:

```bash
cd /home/tyedaprez/gensec-code
uv run --project hw2 python hw2/app.py
```

If you are already in the homework folder:

```bash
cd /home/tyedaprez/gensec-code/hw2
uv run python app.py
```

## Testing with the included test data

The app includes a minimal test corpus in `hw2/test_data`:

- `test_data/txt/answer_key.txt`
- `test_data/pdf/atlas_manual.pdf`

These files are designed to demonstrate retrieval from both a text document and a PDF. Example questions:

```text
What is the project ID for this course?
Who is Atlas?
What does Atlas help students do?
```

The app should answer questions whose content is contained in these files. It should also refuse to answer questions when the relevant fact is not present in the indexed documents.

## Known limitations and warnings

- This app uses the Google Cloud project environment variable and therefore requires valid local Google authentication.
- The LangChain `VertexAIEmbeddings` class emits a deprecation warning in the current package versions; it still works for the course setup.
- The model may emit a warning about direct use of some generation APIs, but the app remains functional for the coursework.
- The app intentionally does not invent an answer when a question is outside the indexed corpus.

## Summary

This Homework 2 app keeps the same retrieval-augmented architecture as the course examples while adding the requested PDF capability and a minimal local test corpus for verification inside `hw2`.
