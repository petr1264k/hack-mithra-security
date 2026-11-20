# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi>=0.162", "uvicorn>=0.54", "python-multipart>=0.0.33", "openai>=3.51,<4",
#                 "psycopg[binary]>=3.3", "boto3>=1.44", "python-dotenv>=1.2.4"]
# ///
"""The workshop demo: upload a text file, ask about it, and see past questions.

    uv run demo/app.py      then open http://localhost:8000

Inference is required. The app uses the database and the bucket once you fill in their lines in .env.
"""
import os
import sys
from pathlib import Path

import boto3
import psycopg
import uvicorn
from botocore.config import Config
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from openai import OpenAI
from pydantic import BaseModel

load_dotenv(override=True)  # reads .env from the repo folder, or next to this file
for name in ("AKAMAI_BASE_URL", "AKAMAI_API_KEY", "CHAT_MODEL"):
    if not os.environ.get(name):
        sys.exit(f"{name} is not set. On a laptop, add it to .env and run uv run check.py. On LKE, remove the # and "
                 "the space after it from the start of the last four lines of 05-lke/deployment.yaml, then apply it again.")

client = OpenAI(base_url=os.environ["AKAMAI_BASE_URL"], api_key=os.environ["AKAMAI_API_KEY"])
DATABASE = bool(os.environ.get("PGHOST"))
BUCKET = os.environ.get("OBJ_BUCKET")
s3 = boto3.client(
    "s3",
    endpoint_url=os.environ.get("OBJ_ENDPOINT"),
    aws_access_key_id=os.environ.get("OBJ_ACCESS_KEY"),
    aws_secret_access_key=os.environ.get("OBJ_SECRET_KEY"),
    config=Config(signature_version="s3v4", request_checksum_calculation="when_required"),  # see 04-object-storage
) if BUCKET else None
MAX_UPLOAD = 1_000_000  # bytes per uploaded file
MAX_CHARS = 20_000  # characters of a file sent to the model
SCHEMA = """create table if not exists questions (
  id bigserial primary key,
  question text not null,
  answer text not null,
  file text,
  created_at timestamptz not null default now()
)"""
app = FastAPI()


def db():
    """A fresh connection with the table in place. psycopg reads the PG settings from the environment."""
    conn = psycopg.connect(connect_timeout=5)
    conn.execute(SCHEMA)
    return conn


def reason(error):
    return f"error: {str(error).strip().splitlines()[0][:150]}"


class Question(BaseModel):
    question: str
    file: str | None = None


@app.get("/", response_class=HTMLResponse)
def page():
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    """connected means one round trip worked in this request. Inference says configured, because a check would spend tokens."""
    status = {"inference": "configured", "database": "not set", "object_storage": "not set"}
    if DATABASE:
        try:
            with db() as conn:
                conn.execute("select 1")
            status["database"] = "connected"
        except Exception as error:
            status["database"] = reason(error)
    if s3:
        try:
            s3.head_bucket(Bucket=BUCKET)
            status["object_storage"] = "connected"
        except Exception as error:
            status["object_storage"] = reason(error)
    return status


@app.post("/ask")
def ask(body: Question):
    question = body.question.strip()
    if not question:
        raise HTTPException(400, "Type a question first.")
    prompt = question
    if body.file:
        if not s3:
            raise HTTPException(400, "No bucket is connected.")
        text = s3.get_object(Bucket=BUCKET, Key=body.file)["Body"].read().decode("utf-8", "replace")
        prompt = f"Use this file, {body.file}, to answer. If it lacks the answer, say so.\n\n{text[:MAX_CHARS]}\n\nQuestion: {question}"
    response = client.chat.completions.create(
        model=os.environ["CHAT_MODEL"],
        messages=[
            {"role": "system", "content": "Answer in a few sentences of plain text, with no Markdown."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=500,
    )
    answer = response.choices[0].message.content or ""
    saved = False
    if DATABASE:
        try:
            with db() as conn:
                conn.execute("insert into questions (question, answer, file) values (%s, %s, %s)",
                             (question, answer, body.file))
            saved = True
        except Exception:
            pass  # the answer still goes back. /health shows the database error
    return {"answer": answer, "saved": saved}


@app.get("/history")
def history():
    if not DATABASE:
        return []
    with db() as conn:
        rows = conn.execute("select question, answer, file, created_at from questions order by id desc limit 20")
        return [{"question": q, "answer": a, "file": f, "created_at": t.isoformat()} for q, a, f, t in rows]


@app.get("/files")
def files():
    if not s3:
        return []
    return [item["Key"] for item in s3.list_objects_v2(Bucket=BUCKET).get("Contents", [])]


@app.post("/files")
async def upload(file: UploadFile):
    if not s3:
        raise HTTPException(400, "No bucket is connected.")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "Files are limited to 1 MB.")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(415, "Upload a text file, such as .txt or .md.")
    key = Path(file.filename or "upload.txt").name
    s3.put_object(Bucket=BUCKET, Key=key, Body=data, ContentType="text/plain; charset=utf-8")
    return {"file": key}


if __name__ == "__main__":  # a server sets PORT. Without it, only this computer can open the app.
    uvicorn.run(app, host="0.0.0.0" if "PORT" in os.environ else "127.0.0.1", port=int(os.environ.get("PORT", 8000)))
