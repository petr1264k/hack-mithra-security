# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi>=0.162", "uvicorn>=0.54", "openai>=3.51,<4", "httpx>=0.28",
#                 "psycopg[binary]>=3.3", "boto3>=1.44", "python-dotenv>=1.2.4"]
# ///
"""Mithra Security: reads the public conversations around the code you depend on and flags takeover risk.

    uv run app.py              then open http://localhost:8000
    uv run app.py --rescan     re-checks saved projects (the nightly systemd timer runs this)

Ground rules: read public data only, never post anywhere, flag situations and never accuse people.
The model tags signals with quotes. Code checks every quote and computes the 0-100 score with fixed weights.
"""
import datetime as dt
import hashlib
import json
import math
import os
import queue
import re
import subprocess
import sys
import threading
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import boto3
import httpx
import psycopg
import uvicorn
from botocore.config import Config
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from openai import OpenAI
from pydantic import BaseModel

HERE = Path(__file__).parent
load_dotenv(HERE / ".env", override=True)
for name in ("AKAMAI_BASE_URL", "AKAMAI_API_KEY", "CHAT_MODEL"):
    if not os.environ.get(name):
        sys.exit(f"{name} is not set. Add it to .env.")

CHAT_MODEL = os.environ["CHAT_MODEL"]                                   # qwen3-8-27b: tags signals as JSON
LONG_MODEL = os.environ.get("VISION_MODEL") or CHAT_MODEL               # gemma-4-26b-a4b-it: reads long threads
EMBED_MODEL = os.environ.get("EMBEDDING_MODEL")                         # qwen3-embedding-8b: xz similarity
ai = OpenAI(base_url=os.environ["AKAMAI_BASE_URL"], api_key=os.environ["AKAMAI_API_KEY"], timeout=120)
DATABASE = bool(os.environ.get("PGHOST"))
BUCKET = os.environ.get("OBJ_BUCKET")
s3 = boto3.client(
    "s3", endpoint_url=os.environ.get("OBJ_ENDPOINT"),
    aws_access_key_id=os.environ.get("OBJ_ACCESS_KEY"), aws_secret_access_key=os.environ.get("OBJ_SECRET_KEY"),
    config=Config(signature_version="s3v4", request_checksum_calculation="when_required"),
) if BUCKET else None
CACHE = HERE / ".cache"
CACHE.mkdir(exist_ok=True)
DATA = HERE / "data"
MAX_DEPS = 15
WINDOW_DAYS = 365


def _gh_token():
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5).stdout.strip() or None
    except Exception:
        return None


GH_TOKEN = _gh_token()
http = httpx.Client(timeout=25, follow_redirects=True, headers={"User-Agent": "mithra-security"})


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()[:32]


def today():
    return dt.date.today().isoformat()


# ---------------------------------------------------------------- storage: disk cache, PostgreSQL, Object Storage

SCHEMA = [
    "create extension if not exists vector",
    """create table if not exists scans (id bigserial primary key, repo text not null,
        created_at timestamptz not null default now(), result jsonb not null)""",
    """create table if not exists risk_history (id bigserial primary key, repo text not null, package text not null,
        dep_repo text, score int, level text, signal_count int, scanned_at timestamptz not null default now())""",
    "create table if not exists saved_projects (repo text primary key, added_at timestamptz not null default now())",
    """create table if not exists signals (id bigserial primary key, dep_repo text not null, type text not null,
        quote text, url text, date text, author text, strength real, found_at timestamptz not null default now(),
        unique (dep_repo, type, url, quote))""",
    "create table if not exists llm_cache (key text primary key, model text, response jsonb, created_at timestamptz default now())",
    """create table if not exists xz_refs (id bigserial primary key, url text, author text, date text,
        body text unique not null, embedding vector(4096) not null)""",
]
_schema_ready = False


def db():
    global _schema_ready
    conn = psycopg.connect(connect_timeout=5, autocommit=True)
    if not _schema_ready:
        for statement in SCHEMA:
            conn.execute(statement)
        _schema_ready = True
    return conn


def disk_get(key):
    path = CACHE / f"{key}.json"
    return json.loads(path.read_text()) if path.exists() else None


def disk_put(key, value):
    (CACHE / f"{key}.json").write_text(json.dumps(value))


def cache_get(key):
    """Model results: disk first, then the shared database so the laptop and the Linode share one cache."""
    hit = disk_get(key)
    if hit is not None:
        return hit
    if DATABASE:
        try:
            with db() as conn:
                row = conn.execute("select response from llm_cache where key = %s", (key,)).fetchone()
            if row:
                disk_put(key, row[0])
                return row[0]
        except Exception:
            pass
    return None


def cache_put(key, model, value):
    disk_put(key, value)
    if DATABASE:
        try:
            with db() as conn:
                conn.execute("insert into llm_cache (key, model, response) values (%s, %s, %s) on conflict (key) do nothing",
                             (key, model, json.dumps(value)))
        except Exception:
            pass


def bucket_put(key, value):
    if not s3:
        return False
    try:
        s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(value, indent=1).encode(), ContentType="application/json")
        return True
    except Exception:
        return False


def bucket_get(key):
    if not s3:
        return None
    try:
        return json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    except Exception:
        return None


def bucket_link(key):
    if not s3:
        return None
    return s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": key}, ExpiresIn=3600)


# ---------------------------------------------------------------- GitHub and package registries (public, read-only)

class RateLimited(Exception):
    pass


def gh(path, params=None):
    """GET from the GitHub API. Cached on disk per day, so a repeat scan costs no requests."""
    url = "https://api.github.com" + path
    key = "gh_" + sha(url + json.dumps(params or {}, sort_keys=True) + today())
    hit = disk_get(key)
    if hit is not None:
        return hit["v"]
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    r = http.get(url, params=params, headers=headers)
    if r.status_code in (403, 429) and r.headers.get("x-ratelimit-remaining") == "0":
        raise RateLimited("GitHub rate limit reached. Try again later.")
    if r.status_code not in (200, 404):  # never cache a rate limit or a server error for the whole day
        return None
    data = r.json() if r.status_code == 200 else None
    disk_put(key, {"v": data})
    return data


def fetch_json(url):
    key = "url_" + sha(url + today())
    hit = disk_get(key)
    if hit is not None:
        return hit["v"]
    r = http.get(url)
    data = r.json() if r.status_code == 200 else None
    disk_put(key, {"v": data})
    return data


def raw(owner, repo, path):
    key = "raw_" + sha(f"{owner}/{repo}/{path}{today()}")
    hit = disk_get(key)
    if hit is not None:
        return hit["v"]
    r = http.get(f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}")
    if r.status_code not in (200, 404):
        return None
    text = r.text if r.status_code == 200 else None
    disk_put(key, {"v": text})
    return text


GH_RE = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$")


def parse_repo(text):
    text = (text or "").strip()
    if text.startswith("github:"):
        text = "github.com/" + text[7:]
    m = GH_RE.search(text)
    if m and m.group(1).lower() not in ("sponsors", "orgs", "apps"):
        return m.group(1), m.group(2)
    m = re.fullmatch(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", text)
    return (m.group(1), m.group(2)) if m else None


def req_name(line):
    line = line.split("#")[0].strip()
    if not line or line.startswith("-") or "://" in line:
        return None
    m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
    return m.group(1) if m else None


def norm_pypi(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def find_deps(owner, repo):
    """Read requirements.txt, pyproject.toml, package.json and PEP 723 script headers from the repo root."""
    tree = gh(f"/repos/{owner}/{repo}/git/trees/HEAD", {"recursive": "1"})
    if not isinstance(tree, dict) or "tree" not in tree:
        raise HTTPException(404, f"Could not read github.com/{owner}/{repo}. Is it public?")
    skip = re.compile(r"(^|/)(node_modules|vendor|\.venv|venv|site-packages|tests?|docs?|examples?)/")
    files = [t["path"] for t in tree["tree"] if t.get("type") == "blob" and t["path"].count("/") <= 2 and not skip.search(t["path"])]
    files.sort(key=lambda f: (f.count("/"), f))
    deps = {}

    def add(eco, name, source):
        if not name:
            return
        name = norm_pypi(name) if eco == "pypi" else name.strip()
        if name in ("python",):
            return
        deps.setdefault((eco, name), source)

    for path in [f for f in files if f.rsplit("/", 1)[-1] == "requirements.txt"][:4]:
        for line in (raw(owner, repo, path) or "").splitlines():
            add("pypi", req_name(line), path)
    for path in [f for f in files if f.rsplit("/", 1)[-1] == "pyproject.toml"][:4]:
        try:
            data = tomllib.loads(raw(owner, repo, path) or "")
            for spec in data.get("project", {}).get("dependencies", []):
                add("pypi", req_name(spec), path)
            for name in data.get("tool", {}).get("poetry", {}).get("dependencies", {}):
                add("pypi", name, path)
        except Exception:
            pass
    for path in [f for f in files if f.rsplit("/", 1)[-1] == "package.json"][:4]:
        try:
            data = json.loads(raw(owner, repo, path) or "{}")
            for name in data.get("dependencies", {}):
                add("npm", name, path)
        except Exception:
            pass
    for path in [f for f in files if f.endswith(".py")][:25]:
        text = raw(owner, repo, path) or ""
        m = re.search(r"(?m)^# /// script\s*\n((?:^#.*\n)+?)^# ///\s*$", text)
        if m:
            body = "\n".join(line[2:] if line.startswith("# ") else line[1:] for line in m.group(1).splitlines())
            try:
                for spec in tomllib.loads(body).get("dependencies", []):
                    add("pypi", req_name(spec), f"{path} (PEP 723)")
            except Exception:
                pass
    items = [{"ecosystem": eco, "package": name, "source": src} for (eco, name), src in deps.items()]
    return items[:MAX_DEPS], items[MAX_DEPS:]


def resolve(eco, name):
    """Map a package to its source repo through the PyPI or npm registry."""
    urls = []
    if eco == "pypi":
        data = fetch_json(f"https://pypi.org/pypi/{name}/json")
        if data:
            info = data.get("info") or {}
            project_urls = info.get("project_urls") or {}
            ranked = sorted(project_urls.items(), key=lambda kv: 0 if re.search(r"source|repo|code|github", kv[0], re.I) else 1)
            urls = [u for _, u in ranked] + [info.get("home_page") or ""]
    else:
        data = fetch_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}/latest")
        if data:
            repository = data.get("repository")
            urls = [repository.get("url", "") if isinstance(repository, dict) else (repository or ""), data.get("homepage") or ""]
    for url in urls:
        found = parse_repo(url or "")
        if found and "github.com" in (url or "") or (found and str(url).startswith("github:")):
            return found
    return None


def funding_links(owner, repo):
    text = raw(owner, repo, ".github/FUNDING.yml") or raw(owner, repo, "FUNDING.yml") or raw(owner, ".github", "FUNDING.yml") or ""
    links = []
    bases = {"github": "https://github.com/sponsors/{}", "open_collective": "https://opencollective.com/{}",
             "patreon": "https://patreon.com/{}", "ko_fi": "https://ko-fi.com/{}", "liberapay": "https://liberapay.com/{}",
             "polar": "https://polar.sh/{}", "buy_me_a_coffee": "https://buymeacoffee.com/{}",
             "tidelift": "https://tidelift.com/subscription/pkg/{}", "custom": "{}"}
    for line in text.splitlines():
        m = re.match(r"\s*([a-z_]+)\s*:\s*(.+)", line.split(" #")[0])
        if not m or m.group(1) not in bases:
            continue
        for value in re.findall(r"[^\[\],'\"\s]+", m.group(2)):
            value = value.replace("tidelift/", "") if m.group(1) != "tidelift" else value.replace("/", "-")
            links.append({"platform": m.group(1), "url": bases[m.group(1)].format(value)})
    return links


def is_bot(user):
    login = (user or {}).get("login", "")
    return not login or login.endswith("[bot]") or (user or {}).get("type") == "Bot" or login.endswith("-bot")


def fetch_activity(owner, repo, fresh=False):
    """About 12 months of public activity for one repo. Archived to Object Storage as the evidence record."""
    archive_key = f"evidence/{owner}/{repo}/{today()}-v2.json"
    if not fresh:
        cached = disk_get("act_" + sha(archive_key)) or bucket_get(archive_key)
        if cached:
            cached["archive_key"] = archive_key
            return cached
    since = (dt.datetime.now(dt.UTC) - dt.timedelta(days=WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    info = gh(f"/repos/{owner}/{repo}") or {}
    issues = gh(f"/repos/{owner}/{repo}/issues", {"state": "all", "since": since, "per_page": 60, "sort": "created", "direction": "desc"}) or []
    comments = gh(f"/repos/{owner}/{repo}/issues/comments", {"since": since, "per_page": 100, "sort": "created", "direction": "desc"}) or []
    commits = gh(f"/repos/{owner}/{repo}/commits", {"since": since, "per_page": 100}) or []
    releases = gh(f"/repos/{owner}/{repo}/releases", {"per_page": 20}) or []
    contributors = gh(f"/repos/{owner}/{repo}/contributors", {"per_page": 15}) or []
    help_wanted = gh(f"/repos/{owner}/{repo}/issues", {"state": "open", "labels": "help wanted", "per_page": 5}) or []
    # the most-discussed threads of the year: a busy repo's 100 newest comments cover only weeks
    hot = gh(f"/repos/{owner}/{repo}/issues", {"state": "all", "since": since, "per_page": 30, "sort": "comments", "direction": "desc"}) or []
    items, seen = [], set()
    threads = []
    for issue in (issues if isinstance(issues, list) else []) + (hot if isinstance(hot, list) else []):
        if is_bot(issue.get("user")) or issue.get("created_at", "") < since or issue["html_url"] in seen:
            continue
        seen.add(issue["html_url"])
        text = f"{issue.get('title', '')}\n{(issue.get('body') or '')[:600]}"
        items.append({"author": issue["user"]["login"], "date": issue["created_at"][:10], "url": issue["html_url"],
                      "assoc": issue.get("author_association"), "text": text})
        if KEYWORDS.search(text) and issue.get("comments", 0):
            threads.append(issue)
    # read the replies of the top maintainer-related threads: pressure and handover happen in the replies
    threads.sort(key=lambda i: i.get("comments", 0), reverse=True)
    thread_comments = []
    for issue in threads[:3]:
        thread_comments += gh(f"/repos/{owner}/{repo}/issues/{issue['number']}/comments", {"per_page": 60}) or []
    for comment in (comments if isinstance(comments, list) else []) + thread_comments:
        if is_bot(comment.get("user")) or comment["html_url"] in seen or comment.get("created_at", "") < since:
            continue
        seen.add(comment["html_url"])
        items.append({"author": comment["user"]["login"], "date": comment["created_at"][:10], "url": comment["html_url"],
                      "assoc": comment.get("author_association"), "text": (comment.get("body") or "")[:600]})
    items.sort(key=lambda i: i["date"], reverse=True)
    commit_authors = {}
    for commit in commits if isinstance(commits, list) else []:
        login = (commit.get("author") or {}).get("login") or commit.get("commit", {}).get("author", {}).get("name", "?")
        if not is_bot(commit.get("author") or {"login": login}):
            commit_authors[login] = commit_authors.get(login, 0) + 1
    activity = {
        "repo": f"{owner}/{repo}", "fetched": today(), "since": since[:10],
        "info": {k: info.get(k) for k in ("description", "stargazers_count", "created_at", "pushed_at", "archived", "owner")},
        "items": items[:250],
        "commit_authors": commit_authors,
        "releases": [{"tag": r.get("tag_name"), "author": (r.get("author") or {}).get("login"), "date": (r.get("published_at") or "")[:10],
                      "url": r.get("html_url"), "bot": is_bot(r.get("author"))} for r in releases if isinstance(r, dict)],
        "contributors": [{"login": c.get("login"), "contributions": c.get("contributions"), "avatar": c.get("avatar_url")}
                         for c in contributors if isinstance(c, dict) and not is_bot(c)] if isinstance(contributors, list) else [],
        "help_wanted": [{"title": i.get("title"), "url": i.get("html_url")} for i in help_wanted if isinstance(i, dict)],
        "funding": funding_links(owner, repo),
    }
    if isinstance(activity["info"].get("owner"), dict):
        activity["info"]["owner"] = activity["info"]["owner"].get("login")
    disk_put("act_" + sha(archive_key), activity)
    activity["archived"] = bucket_put(archive_key, activity)
    activity["archive_key"] = archive_key
    return activity


def account_created(login):
    user = gh(f"/users/{login}")
    return (user or {}).get("created_at", "")[:10] or None


# ---------------------------------------------------------------- inference: tag signals, check quotes, embeddings

TYPES = ["maintainer_burnout", "pressure_campaign", "control_handover"]
TAG_SCHEMA = {
    "type": "object",
    "properties": {"signals": {"type": "array", "items": {
        "type": "object",
        "properties": {"item": {"type": "integer"}, "type": {"type": "string", "enum": TYPES},
                       "quote": {"type": "string"}, "why": {"type": "string"}},
        "required": ["item", "type", "quote", "why"], "additionalProperties": False}}},
    "required": ["signals"], "additionalProperties": False,
}
TAG_PROMPT = """You review public open-source project conversations for early signs of a maintainer takeover,
like the 2022 xz Utils pressure campaign. You flag situations, never accuse people.

Signal types:
- maintainer_burnout: a maintainer says they lack time or energy, are stepping back, are overwhelmed, that the
  project is unpaid or unmaintained, or that they are looking for help or a new maintainer.
- pressure_campaign: someone pushes the maintainer: complains about slow progress or unmerged patches, says the
  project is dead or neglected, or demands a new or additional maintainer or that access be handed over.
- control_handover: someone is given, offered or asks for commit, merge, release or maintainer rights.

Most messages are ordinary bug reports, patches and questions. Do NOT flag them. NOT pressure: a polite
"any update?" or "any chance this gets merged?", bumping or rebasing your own pull request, asking for a review,
offering to help, closing or giving up on your own pull request. Pressure criticizes the maintainer or the pace of
the whole project, or demands a new maintainer. NOT handover: taking over a single pull request or issue, asking
to collaborate on a fork or a branch, or a CI/bot account; a handover is about rights over the whole project.
NOT burnout: "I'll get to it when I have time" about one item, or a user saying they no longer use the project.
Only flag clear cases. For each flag give the item number, the type, an EXACT quote copied from that
item (one sentence, verbatim) and a short reason. Return an empty list if nothing qualifies."""


def norm(text):
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def tag_items(items, model=CHAT_MODEL):
    """Ask the model for signals, then keep only those whose quote really appears in the cited item."""
    if not items:
        return [], 0
    numbered = "\n\n".join(f"[{n}] {i['date']} {i['author']}:\n{i['text'][:700]}" for n, i in enumerate(items))
    key = "tag_" + sha(model + TAG_PROMPT + numbered)
    result = cache_get(key)
    if result is None:
        response = ai.chat.completions.create(
            model=model, temperature=0, max_tokens=3000,
            messages=[{"role": "system", "content": TAG_PROMPT}, {"role": "user", "content": numbered}],
            response_format={"type": "json_schema", "json_schema": {"name": "signals", "schema": TAG_SCHEMA}},
        )
        choice = response.choices[0]
        if choice.finish_reason != "stop":  # a cut-off reply is not valid JSON
            return [], 0
        try:
            result = json.loads(choice.message.content)
        except Exception:
            return [], 0
        cache_put(key, model, result)
    kept, rejected = [], 0
    for s in result.get("signals", []):
        n = s.get("item")
        if not isinstance(n, int) or not 0 <= n < len(items) or s.get("type") not in TYPES:
            rejected += 1
            continue
        quote = s.get("quote", "").strip().strip('"')
        if len(norm(quote)) < 8 or norm(quote)[:120] not in norm(items[n]["text"]):
            rejected += 1  # the model's quote is not in the source: drop it rather than show an invented quote
            continue
        item = items[n]
        at = item["text"].find(quote)
        if at >= 0:  # the model sometimes stops mid-word; finish the word from the source
            end = at + len(quote)
            while end < len(item["text"]) and end - at < len(quote) + 30 and item["text"][end].isalnum():
                end += 1
            quote = item["text"][at:end]
            body = item["text"] if "#issuecomment-" in item["url"] else item["text"].split("\n", 1)[-1]
            if end >= len(item["text"]) and len(body) >= 600:  # the fetch keeps 600 characters of each message
                quote += "…"
        kept.append({"type": s["type"], "quote": quote, "why": s.get("why", ""), "author": item["author"],
                     "date": item["date"], "url": item["url"], "strength": 1.0, "assoc": item.get("assoc")})
    return kept, rejected


def embed(texts):
    if not EMBED_MODEL or not texts:
        return []
    out = [None] * len(texts)
    todo = []
    for n, text in enumerate(texts):
        hit = disk_get("emb_" + sha(text))
        if hit:
            out[n] = hit
        else:
            todo.append(n)
    for start in range(0, len(todo), 32):
        batch = todo[start:start + 32]
        response = ai.embeddings.create(model=EMBED_MODEL, input=[texts[n][:2000] for n in batch])
        for n, item in zip(batch, response.data):
            out[n] = item.embedding
            disk_put("emb_" + sha(texts[n]), item.embedding)
    return out


def vec(v):
    return "[" + ",".join(map(str, v)) + "]"


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    return dot / (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)) or 1)


XZ_REFS_FALLBACK = [
    {"author": "Jigar Kumar", "date": "2022-06", "url": "https://www.mail-archive.com/xz-devel@tukaani.org/",
     "text": "Progress will not happen until there is new maintainer. The current maintainer lost interest or doesn't care to maintain anymore."},
    {"author": "Jigar Kumar", "date": "2022-06", "url": "https://www.mail-archive.com/xz-devel@tukaani.org/",
     "text": "Why wait until 5.4.0 to change maintainer? Why delay what your repo needs?"},
    {"author": "Dennis Ens", "date": "2022-06", "url": "https://www.mail-archive.com/xz-devel@tukaani.org/",
     "text": "Why not pass on maintainership so you can give the project more attention? The community desires more."},
]
# Calibrated on our data: xz pressure emails score 0.57-0.76 against each other (leave one out);
# ordinary python-dotenv comments top out at 0.66.
SIM_THRESHOLD = float(os.environ.get("XZ_SIM_THRESHOLD", "0.70"))


def xz_references():
    path = DATA / "xz_replay.json"
    if path.exists():
        refs = [m for m in json.loads(path.read_text())["messages"] if m.get("kind") == "pressure"]
        if refs:
            return refs
    return XZ_REFS_FALLBACK


_refs_loaded = None


def load_refs():
    """Embed the 2022 xz pressure emails once and keep them in pgvector."""
    global _refs_loaded
    if _refs_loaded is not None:
        return _refs_loaded
    refs = xz_references()
    vectors = embed([r["text"] for r in refs])
    if DATABASE and vectors:
        try:
            with db() as conn:
                for r, v in zip(refs, vectors):
                    conn.execute("insert into xz_refs (url, author, date, body, embedding) values (%s, %s, %s, %s, %s::vector) "
                                 "on conflict (body) do nothing", (r["url"], r["author"], r["date"], r["text"], vec(v)))
        except Exception:
            pass
    _refs_loaded = list(zip(refs, vectors))
    return _refs_loaded


def xz_similar(items):
    """Items whose meaning is close to a 2022 xz pressure email. pgvector does the search when the database is up."""
    refs = load_refs()
    if not refs or not items:
        return []
    seen, unique = set(), []
    for i in items:  # short replies ("Won't fix.") carry no meaning to compare, and repeats count once
        if len(i["text"].strip()) >= 40 and i["url"] not in seen:
            seen.add(i["url"])
            unique.append(i)
    items = unique
    vectors = embed([i["text"][:1500] for i in items])
    found = []
    conn = None
    if DATABASE:
        try:
            conn = db()
        except Exception:
            conn = None
    try:
        for item, v in zip(items, vectors):
            if conn:
                row = conn.execute("select body, url, author, date, 1 - (embedding <=> %s::vector) from xz_refs "
                                   "order by embedding <=> %s::vector limit 1", (vec(v), vec(v))).fetchone()
                best = {"text": row[0], "url": row[1], "author": row[2], "date": row[3]}, row[4]
            else:
                best = max(((r, cosine(v, rv)) for r, rv in refs), key=lambda x: x[1])
            if best[1] >= SIM_THRESHOLD:
                found.append({"type": "xz_similarity", "quote": item["text"][:240].strip(), "author": item["author"],
                              "assoc": item.get("assoc"),
                              "date": item["date"], "url": item["url"], "strength": 1.0, "similarity": round(best[1], 3),
                              "why": f"Reads like the 2022 xz email by {best[0]['author']}: \"{best[0]['text'][:140]}\""})
    finally:
        if conn:
            conn.close()
    return found


# ---------------------------------------------------------------- scoring: code, not the model

WEIGHTS = {"maintainer_burnout": 20, "pressure_campaign": 20, "control_handover": 30, "xz_similarity": 10}
CAPS = {"maintainer_burnout": 30, "pressure_campaign": 40, "control_handover": 30, "xz_similarity": 20}
COMBO_BONUS = 15  # burnout and pressure in the same window: the xz pattern


def score(signals, item_count):
    per = {t: min(CAPS[t], round(sum(WEIGHTS[t] * s.get("strength", 1) for s in signals if s["type"] == t)))
           for t in WEIGHTS}
    combo = COMBO_BONUS if per["maintainer_burnout"] and per["pressure_campaign"] else 0
    if item_count < 5 and not signals:
        return {"score": None, "level": "unknown", "label": "not enough data", "breakdown": per, "combo": 0}
    total = min(100, sum(per.values()) + combo)
    level = "red" if total >= 60 else "yellow" if total >= 30 else "green"
    return {"score": total, "level": level, "label": level, "breakdown": per, "combo": combo}


KEYWORDS = re.compile(r"maintain|step(ping)? (down|back)|no (longer )?(have )?time|burn(ed|t)? ?out|abandon|\bdead\b|"
                      r"take over|taking over|hand(ing)? over|new owner|commit (access|rights)|merge rights|release rights|"
                      r"collaborator|co-?maintainer|looking for help|transfer (the )?(repo|project|ownership)", re.I)
MAINTAINER_ROLES = {"OWNER", "MEMBER", "COLLABORATOR"}
NEWCOMER_ROLES = {"NONE", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER"}


def select_items(items, limit=60):
    """Maintainer-related messages first (by keyword), then the newest. Keeps model calls small."""
    keyed = [i for i in items if KEYWORDS.search(i["text"])][:40]
    rest = [i for i in items if i not in keyed][:limit - len(keyed)]
    return sorted(keyed + rest, key=lambda i: i["date"])


# Someone warning about another account is defending the project, not pressuring it.
WARNING_RE = re.compile(r"supply[- ]chain attack|\bbe wary\b|\bwary of\b|\bbeware\b|\bhoneypot\b|\bnot authentic|"
                        r"\bimpersonat|\bsock ?puppet|\bscam\b|\bmalicious\b|\bsuspicious\b|left on \d+ other repos", re.I)
# Removing or revoking access is the opposite of a handover.
REVOKE_RE = re.compile(r"\b(remov|revok)\w*\b[^.]{0,40}\b(access|rights|permissions?)\b", re.I)


def mislabelled(s, text):
    if s["type"] in ("pressure_campaign", "xz_similarity") and WARNING_RE.search(text):
        return True
    return s["type"] == "control_handover" and bool(REVOKE_RE.search(s["quote"]))


def analyze_dependency(dep, fresh=False):
    out = dict(dep)
    found = tuple(dep["repo"].split("/")) if dep.get("repo") else resolve(dep["ecosystem"], dep["package"])
    if not found:
        out.update(repo=None, score=None, level="unknown", label="not enough data", signals=[],
                   note="No public GitHub source repo listed in the registry.")
        return out
    owner, repo = found
    out["repo"] = f"{owner}/{repo}"
    activity = fetch_activity(owner, repo, fresh=fresh)
    items = activity["items"]
    chosen = select_items(items)
    signals, rejected = tag_items(chosen)
    maintainers = {c["login"] for c in activity["contributors"][:5]} | {activity["info"].get("owner")}
    maintainers |= {i["author"] for i in items if i.get("assoc") in MAINTAINER_ROLES}
    for s in signals:  # code adjusts strength from facts, not from the model
        if s["type"] == "pressure_campaign":
            if s.get("assoc") in NEWCOMER_ROLES:
                s["note"] = "no prior contributions to this repo"
            else:  # in xz the pressure came from brand-new names; a known contributor's nudge counts half
                s["strength"] = 0.5
                s["note"] = "half weight: a known contributor"
        if s["type"] == "maintainer_burnout" and s["author"] not in maintainers:
            s["strength"] = 0
            s["note"] = "not counted: not from a maintainer"
        if s["type"] == "control_handover" and s["author"] not in maintainers:
            s["strength"] = 0.5
            s["note"] = "half weight: not said by a maintainer"
        if s["type"] == "pressure_campaign":
            if s["author"] in maintainers:
                s["strength"] = 0.5
                s["note"] = "from a maintainer"
    for login in list(dict.fromkeys(s["author"] for s in signals if s["type"] == "pressure_campaign"))[:5]:
        created = account_created(login)
        for s in signals:
            if s["author"] == login and s["type"] == "pressure_campaign" and created:
                s["account_created"] = created
                if (dt.date.fromisoformat(s["date"]) - dt.date.fromisoformat(created)).days < 365:
                    s["strength"] = 1.5 if s.get("assoc") in NEWCOMER_ROLES else 0.75
                    s["note"] = "account less than a year old"
    signals += handover_from_releases(activity)
    # a maintainer's own words are not a pressure campaign, however they read
    tagged = {s["url"] for s in signals}  # one message counts once
    # as in xz, where the pressure came from brand-new names, only newcomers' messages are compared
    signals += [s for s in xz_similar(chosen) if s["author"] not in maintainers and s["url"] not in tagged
                and s.get("assoc") in NEWCOMER_ROLES]
    text_of = {i["url"]: i["text"] for i in chosen}
    signals = [s for s in signals if not mislabelled(s, text_of.get(s["url"], s["quote"]))]  # code drops two known mislabels
    out["signals"] = sorted(signals, key=lambda s: s["date"])
    out["rejected_quotes"] = rejected
    out["item_count"] = len(items)
    out["read_count"] = len(chosen)
    out["item_dates"] = [i["date"] for i in items]  # for the dashboard's week-by-week map
    out.update(score(signals, len(items) + len(activity["releases"])))
    out["adopt"] = adopt_card(activity, signals)
    out["archive_key"] = activity.get("archive_key")
    out["stars"] = activity["info"].get("stargazers_count")
    return out


def handover_from_releases(activity):
    """A newcomer starts publishing releases that someone else used to publish."""
    releases = [r for r in activity["releases"] if r["author"] and not r["bot"] and r["date"]]
    if len(releases) < 2:
        return []
    since = activity["since"]
    recent = [r for r in releases if r["date"] >= since]
    older_authors = {r["author"] for r in releases if r["date"] < since}
    top = {c["login"] for c in activity["contributors"][:10]}
    signals = []
    for r in recent:
        if older_authors and r["author"] not in older_authors and r["author"] not in top:
            signals.append({"type": "control_handover", "quote": f"Release {r['tag']} published by {r['author']}, "
                            f"who did not publish earlier releases (earlier: {', '.join(sorted(older_authors))}).",
                            "author": r["author"], "date": r["date"], "url": r["url"], "strength": 1.0,
                            "why": "A new person has release rights and is not a top contributor."})
            break
    return signals


def adopt_card(activity, signals):
    """Shown only when a maintainer said publicly they are stretched thin. Links where they said it."""
    asks = [x for x in signals if x["type"] == "maintainer_burnout" and x.get("strength", 1) > 0]
    if not asks:
        return None
    ask = asks[-1]
    commits = {k: v for k, v in activity["commit_authors"].items() if not re.search(r"bot|automation", k, re.I)}
    total = sum(commits.values())
    mine = commits.get(ask["author"], 0)
    return {"login": ask["author"], "asked_on": ask["date"], "quote": ask["quote"], "url": ask["url"],
            "share": round(mine / total, 2) if total else None, "commits": mine, "total_commits": total,
            "avatar": f"https://github.com/{ask['author']}.png?size=80", "funding": activity["funding"],
            "help_wanted": activity["help_wanted"]}


def scan(repo_text, fresh=False, events=None):
    """events: optional callback that gets live progress (called from worker threads)."""
    emit = events or (lambda event: None)
    found = parse_repo(repo_text)
    if not found:
        raise HTTPException(400, "Paste a GitHub repo, like https://github.com/owner/name.")
    owner, repo = found
    deps, skipped = find_deps(owner, repo)
    deps = [{"ecosystem": "github", "package": f"{repo} (this repo)", "source": "the repo you pasted",
             "repo": f"{owner}/{repo}"}] + deps
    emit({"step": "deps", "repo": f"{owner}/{repo}", "packages": [d["package"] for d in deps]})

    def run(dep):
        r = analyze_dependency(dep, fresh)
        emit({"step": "dep", "package": dep["package"], "repo": r.get("repo"), "level": r["level"], "score": r["score"],
              "read": r.get("read_count", 0), "items": r.get("item_count", 0), "rejected": r.get("rejected_quotes", 0),
              "signals": sum(1 for s in r.get("signals", []) if s.get("strength", 1) > 0)})
        return r
    with ThreadPoolExecutor(6) as pool:
        results = list(pool.map(run, deps))
    me = f"{owner}/{repo}".lower()  # a monorepo can depend on its own package: score the repo once
    results = results[:1] + [r for r in results[1:] if (r.get("repo") or "").lower() != me]
    order = {"red": 0, "yellow": 1, "green": 2, "unknown": 3}
    results.sort(key=lambda r: (order[r["level"]], -(r["score"] or 0)))
    report = {"repo": f"{owner}/{repo}", "scanned": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
              "dependencies": results, "skipped": [d["package"] for d in skipped],
              "weights": WEIGHTS, "caps": CAPS, "combo_bonus": COMBO_BONUS}
    report["id"] = save_scan(report)
    report_key = f"reports/{owner}/{repo}/{report['scanned'][:19].replace(':', '')}.json"
    if bucket_put(report_key, report):
        report["report_link"] = bucket_link(report_key)
    return report


def save_scan(report):
    if not DATABASE:
        return None
    try:
        with db() as conn:
            scan_id = conn.execute("insert into scans (repo, result) values (%s, %s) returning id",
                                   (report["repo"], json.dumps(report))).fetchone()[0]
            for d in report["dependencies"]:
                conn.execute("insert into risk_history (repo, package, dep_repo, score, level, signal_count) values (%s,%s,%s,%s,%s,%s)",
                             (report["repo"], d["package"], d.get("repo"), d.get("score"), d["level"], len(d.get("signals", []))))
                for s in d.get("signals", []):
                    conn.execute("insert into signals (dep_repo, type, quote, url, date, author, strength) values (%s,%s,%s,%s,%s,%s,%s) "
                                 "on conflict do nothing", (d["repo"], s["type"], s["quote"], s["url"], s["date"], s["author"], s["strength"]))
            return scan_id
    except Exception as error:
        print("database:", error)
        return None


# ---------------------------------------------------------------- xz replay: month by month through xz-devel

REPLAY_KEY = "replay/xz_replay.json"


def replay_dataset():
    data = bucket_get(REPLAY_KEY)
    local = DATA / "xz_replay.json"
    if local.exists():
        local_data = json.loads(local.read_text())
        if data != local_data:
            bucket_put(REPLAY_KEY, local_data)  # Object Storage holds the dataset the server reads
        data = local_data
    return data


def months_between(start, end):
    y, m = map(int, start.split("-"))
    out = []
    while f"{y:04d}-{m:02d}" <= end:
        out.append(f"{y:04d}-{m:02d}")
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def run_replay():
    data = replay_dataset()
    if not data:
        raise HTTPException(503, "The xz dataset is not loaded yet.")
    messages = sorted(data["messages"], key=lambda m: m["date"])
    key = "replay_" + sha(json.dumps(messages) + TAG_PROMPT + json.dumps(WEIGHTS) + "v2")
    cached = cache_get(key) if "--fresh" not in sys.argv else None
    if cached:
        return cached
    first_seen = {}
    for m in messages:
        first_seen.setdefault(m["author"], m["date"])
    items = [{"author": m["author"], "date": m["date"], "url": m["url"], "text": f"Subject: {m['subject']}\n{m['text']}"}
             for m in messages]  # the human "kind" label is never shown to the model
    months = months_between(messages[0]["date"][:7], messages[-1]["date"][:7])
    by_month = {mo: [i for i in items if i["date"].startswith(mo)] for mo in months}

    def tag_month(month):
        return month, tag_items(by_month[month], model=LONG_MODEL) if by_month[month] else ([], 0)

    with ThreadPoolExecutor(8) as pool:
        tagged = dict(pool.map(tag_month, months))
    all_signals = []
    timeline = []
    for month in months:
        new, rejected = tagged[month]
        for s in new:
            if s["type"] == "pressure_campaign":
                days = (dt.date.fromisoformat(s["date"]) - dt.date.fromisoformat(first_seen[s["author"]])).days
                if days < 180:
                    s["strength"] = 1.5
                    s["note"] = "their first message on the list" if days == 0 else f"new to the list: first message {days} days earlier"
        all_signals += new
        window_start = months_between("2000-01", month)[-12]
        # burnout and pressure fade after 12 months; a handover of control is lasting, so it stays
        window = [s for s in all_signals if s["date"][:7] <= month and
                  (window_start <= s["date"][:7] or s["type"] == "control_handover")]
        result = score(window, sum(len(by_month[mo]) for mo in months if window_start <= mo <= month) + 5)
        timeline.append({"month": month, "messages": len(by_month[month]), "new_signals": new,
                         "rejected_quotes": rejected, **result})
    first_red = next((t["month"] for t in timeline if t["level"] == "red"), None)
    out = {"timeline": timeline, "first_red": first_red, "backdoor": "2024-02", "disclosure": "2024-03-29",
           "source": data.get("archive_url"), "model": LONG_MODEL, "message_count": len(messages)}
    cache_put(key, LONG_MODEL, out)
    bucket_put("replay/xz_result.json", out)
    return out


# ---------------------------------------------------------------- web app

app = FastAPI()


class ScanRequest(BaseModel):
    repo: str
    fresh: bool = False


@app.get("/", response_class=HTMLResponse)
def page():
    return (HERE / "index.html").read_text(encoding="utf-8")


def reason(error):
    return f"error: {str(error).strip().splitlines()[0][:150]}"


@app.get("/health")
def health():
    status = {"inference": "configured", "database": "not set", "object_storage": "not set",
              "github": "token" if GH_TOKEN else "anonymous (60 requests/hour)"}
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


@app.post("/api/scan")
def api_scan(body: ScanRequest):
    try:
        return scan(body.repo, fresh=body.fresh)
    except RateLimited as error:
        raise HTTPException(429, str(error))


@app.post("/api/scan/stream")
def api_scan_stream(body: ScanRequest):
    """The same scan, sent as one JSON line per step, so the page can show the real progress."""
    if not parse_repo(body.repo):
        raise HTTPException(400, "Paste a GitHub repo, like https://github.com/owner/name.")
    events = queue.Queue()

    def work():
        try:
            events.put({"step": "done", "report": scan(body.repo, fresh=body.fresh, events=events.put)})
        except (HTTPException, RateLimited) as error:
            events.put({"step": "error", "detail": getattr(error, "detail", None) or str(error)})
        except Exception as error:  # report it in the stream: the page is already showing progress
            events.put({"step": "error", "detail": f"The scan failed: {error}"})
    threading.Thread(target=work, daemon=True).start()

    def lines():
        while True:
            event = events.get()
            yield json.dumps(event, default=str) + "\n"
            if event["step"] in ("done", "error"):
                return
    return StreamingResponse(lines(), media_type="application/x-ndjson")


@app.get("/api/scans")
def api_scans():
    if not DATABASE:
        return []
    with db() as conn:
        rows = conn.execute("select id, repo, created_at, result from scans order by id desc limit 15").fetchall()
    return [{"id": i, "repo": r, "created_at": t.isoformat(),
             "levels": [d["level"] for d in res["dependencies"]]} for i, r, t, res in rows]


@app.get("/api/scans/{scan_id}")
def api_scan_get(scan_id: int):
    with db() as conn:
        row = conn.execute("select result from scans where id = %s", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "No such scan.")
    return {**row[0], "id": scan_id}


@app.get("/api/history")
def api_history(repo: str, package: str):
    if not DATABASE:
        return []
    with db() as conn:
        rows = conn.execute("select score, level, scanned_at from risk_history where repo = %s and package = %s "
                            "order by scanned_at limit 200", (repo, package)).fetchall()
    return [{"score": s, "level": lv, "at": t.isoformat()} for s, lv, t in rows]


@app.post("/api/save")
def api_save(body: ScanRequest):
    found = parse_repo(body.repo)
    if not found or not DATABASE:
        raise HTTPException(400, "Paste a GitHub repo first.")
    with db() as conn:
        conn.execute("insert into saved_projects (repo) values (%s) on conflict do nothing", ("/".join(found),))
    return {"saved": "/".join(found)}


@app.get("/api/saved")
def api_saved():
    if not DATABASE:
        return []
    with db() as conn:
        return [r for (r,) in conn.execute("select repo from saved_projects order by added_at").fetchall()]


@app.get("/api/replay")
def api_replay():
    return run_replay()


@app.get("/api/evidence")
def api_evidence(key: str):
    """Redirect to a one-hour presigned link for an evidence archive in Object Storage."""
    if not key.startswith(("evidence/", "reports/", "replay/")) or ".." in key:
        raise HTTPException(400, "Unknown evidence key.")
    link = bucket_link(key)
    if not link:
        raise HTTPException(404, "No bucket connected.")
    return RedirectResponse(link)


def rescan_saved():
    """Run by the nightly systemd timer on the Linode."""
    with db() as conn:
        repos = [r for (r,) in conn.execute("select repo from saved_projects").fetchall()]
    for repo in repos:
        try:
            report = scan(repo, fresh=True)
            print(repo, [(d["package"], d["score"]) for d in report["dependencies"]])
        except Exception as error:
            print(repo, "failed:", reason(error))


if __name__ == "__main__":
    if "--rescan" in sys.argv:
        rescan_saved()
    elif "--replay" in sys.argv:
        result = run_replay()
        for t in result["timeline"]:
            print(t["month"], t["messages"], t["score"], t["level"], [s["type"] for s in t["new_signals"]])
        print("first red:", result["first_red"])
    else:
        uvicorn.run(app, host="0.0.0.0" if "PORT" in os.environ else "127.0.0.1", port=int(os.environ.get("PORT", 8000)))
