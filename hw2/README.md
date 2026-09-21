# Homework 2 RAG app

This folder contains the baseline RAG application for Homework 2, including PDF support.

## Requirements

This app uses the same core LangChain RAG architecture as the course examples in `02_LangChain/07_RAG` and depends on Google Cloud / Vertex AI configuration for embeddings.

## Environment configuration

Before running the app, set the required environment variables without placing secrets in source control:

```bash
export GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
export GOOGLE_MODEL="gemini-2.0-flash"
```

If your environment uses a different variable name, you may also set:

```bash
export GCP_PROJECT_ID="your-gcp-project-id"
```

The application also expects Google Cloud authentication to be enabled for the local environment, for example via `gcloud auth application-default login` or an equivalent ADC setup.

## Run with uv

From the repository root:

```bash
cd /home/tyedaprez/gensec-code
uv run --project hw2 python hw2/app.py
```

If you are already in the `hw2` directory:

```bash
cd /home/tyedaprez/gensec-code/hw2
uv run python app.py
```

## Notes

- The app intentionally preserves the course RAG workflow and adds PDF support.
- No API keys or credentials are stored in the project files.
- The startup path expects the course data folder at `../02_LangChain/07_RAG/rag_data`.
