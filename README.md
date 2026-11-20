# <img src="logo.svg" width="32" height="32" alt=""> Mithra Security

Mithra Security reads the public conversations around the open-source code your app depends on, and warns you when a project looks like it is being taken over, before any bad code exists.

Built at **Build with Akamai Cloud: Seattle — AI Workshop & Buildathon**, November 20, 2026, GitHub Bellevue.

**Team:** Petr Kirsanov and Petr's dad.

Starts from the workshop demo app in [akamai-developers/akamai-workshop-seattle-hackathon](https://github.com/akamai-developers/akamai-workshop-seattle-hackathon).

## Why

In 2024, a backdoor in **xz Utils** (CVE-2024-3094) nearly reached millions of Linux servers. It was caught by luck: an engineer noticed that SSH logins were about half a second slow. The code was the last step of a two-year con. In 2022, new accounts on the public xz-devel mailing list pressed the tired, unpaid maintainer to hand over control, and he said that someone else might take a bigger role. Security scanners read code. This attack showed up first in conversation, and Mithra reads the conversation.

It wasn't a one-off. In 2018 the burned-out maintainer of the npm package event-stream handed it to a stranger who offered to help, and the new owner shipped code that stole bitcoin from a wallet app. Weeks after xz, in April 2024, the OpenJS Foundation reported emails pressing it to make strangers maintainers of a popular JavaScript project.

## Submission

```text
User and task: Developers and security teams who ship apps built on open-source
libraries. They need to know which of their dependencies are at risk of a hostile
takeover, before a bad release reaches them.

Benefit: Paste a GitHub repo and get every dependency scored 0-100, with the exact
public quotes and links behind each score. Projects to watch can be re-scanned every
night. When a maintainer has asked for help, Mithra shows where to support them.

Services:
- Linode (Nanode, Seattle) runs the FastAPI app as a systemd service, plus a systemd
  timer that re-scans watched repos every night and records their risk history.
- Managed PostgreSQL 18 stores scans, per-dependency risk history, tagged signals,
  watched repos, a shared cache of model results, and the 2022 xz pressure emails
  as 4,096-dimension pgvector embeddings for similarity search.
- Object Storage keeps the evidence: each project's fetched public activity (one
  archive per project per day, opened from the dashboard through a one-hour
  presigned link), every scan report, and the xz replay dataset and its results.
- Akamai Cloud Inference runs all three models (below).

Inference:
- qwen3-8-27b tags signals (maintainer burnout, pressure campaign, control handover)
  in GitHub issues and comments, as JSON matched to a schema. We check
  finish_reason == "stop" before parsing.
- gemma-4-26b-a4b-it reads the xz-devel mailing list month by month, because its
  262k-token context fits whole threads.
- qwen3-embedding-8b embeds messages. pgvector finds the ones closest to the 2022 xz
  pressure emails.
How we checked it:
- Every quote the model returns must appear word for word in the cited message, or
  code drops it. The dashboard shows how many were rejected.
- Known answer: the xz replay turns red in May 2022, 21 months before the backdoor
  shipped in February 2024.
- Controls: Flask's dependencies and the workshop repo's dependencies all score low.
  Earlier versions flagged them; we read every quote, found false positives
  ("any chance this gets merged?", "should I take over [this PR]?") and tightened
  the rules until the controls stayed green.
- Input it can't answer: the workshop repo itself and the srp package have too
  little public conversation in the last year. Both show "not enough data" with no
  score, instead of a guess.
- The similarity threshold (0.70) is calibrated on our data. The xz pressure emails
  score 0.57-0.76 against each other; ordinary python-dotenv comments top out at
  0.66.

Technical choice:
- Code computes the risk score, not the model. Fixed weights: burnout 20 (max 30),
  pressure 20 (max 40), handover 30 (max 30), xz-like message 10 (max 20), plus 15
  when burnout and pressure appear together. Low under 30, watch 30-59, high 60+.
  Code also adjusts each signal using facts from GitHub. Burnout counts only when a
  maintainer says it. A nudge from a known contributor counts half. Pressure from a
  brand-new account counts 1.5 times.
- Caching protects the shared AI key and GitHub's rate limit. Model results are
  cached by content hash on disk and in PostgreSQL, so the laptop and the Linode
  share them. GitHub responses are cached per day. Rate-limit errors are never
  cached.
- The server never holds the account API token. deploy.sh strips it before copying
  .env.
- The Object Storage key can only read and write this one bucket.
- The database allow list has the Linode's IPv4 and IPv6 addresses. Adding IPv6
  removed a 5-second connection delay.
- The server runs on Pacific time, so day-keyed caches don't all expire at 4 PM
  during the demo.

Our idea: Existing tools look at code or at activity numbers. Socket.dev alerts after
a new author publishes a package. OpenSSF Scorecard and CHAOSS measure activity.
Mithra reads the conversation and catches the pressure campaign before the handover,
which for xz was about two years before the backdoor. It flags situations, never
people, shows the evidence behind every flag, and ends with "adopt a maintainer":
well-supported maintainers are the real defence.

Demo (each saved scan opens straight from its link, with no live scan):
1. http://172.232.189.84/#scan=50 binbin2000/icloudpd-manager, a small app. 14 of its
   16 dependencies score low; its icloudpd library scores high (60). That project's
   maintainers posted "Looking for new MAINTAINER for the project" and "I'm very busy
   at the moment and don't have much time for the project".
2. http://172.232.189.84/#scan=46 tzezar/datagrid scores high (60). The owner wrote
   "I no longer have enough time to actively maintain or develop this project". The
   adopt-a-maintainer card links to the owner's GitHub Sponsors and Buy Me a Coffee.
3. http://172.232.189.84/#scan=35 mistletoe scores watch (50): a maintainer stepping
   back and an open handover to a known contributor, with no pressure from strangers.
4. http://172.232.189.84/#scan=38 the workshop repo. Its 7 dependencies score low,
   and the repo itself shows "not enough data".
5. http://172.232.189.84/#replay then Play. The risk climbs as the 2022 pressure
   emails arrive and turns red in May 2022, 21 months before the backdoor shipped.

Known limits:
- Reads the last 12 months, and at most 60 messages per project per scan
  (maintainer-related threads first). The xz replay uses a fixed dataset of 45
  emails we collected and checked by hand.
- GitHub doesn't publish permission changes, so a handover is inferred from
  conversations and from who publishes releases.
- Finds dependencies in requirements.txt, pyproject.toml, package.json and PEP 723
  script headers, up to two folders deep and 15 per repo. No lockfiles, and no
  dependencies of dependencies.
- The Linode has no GitHub token, so it gets 60 GitHub requests an hour. Scans are
  cached, but a brand-new large repo can hit the limit.
- The model still labels some polite requests ("could we get this merged?") as
  pressure, and once labelled a contributor's warning about attackers as pressure.
  Code halves pressure from known contributors, but a false alarm can still raise a
  score. That is why every flag shows its quote and link.
- English only.
```

## How it works

1. **Scan.** Find dependencies in `requirements.txt`, `pyproject.toml`, `package.json` and PEP 723 `# /// script` headers, using one GitHub tree request.
2. **Resolve.** Map each package to its GitHub repo through the PyPI JSON API or the npm registry. The pasted repo is scored too.
3. **Fetch.** About 12 months of public activity: issues, comments, the year's most-discussed threads and their replies, commits, releases, contributors, `FUNDING.yml` and "help wanted" issues. Each archive goes to Object Storage.
4. **Tag.** The model tags signals with quotes. Code checks every quote and adds facts from GitHub (whether the author is a maintainer or new to the project, and how old their account is).
5. **Score.** Code computes 0–100 with fixed weights.
6. **Show.** The dashboard shows a weekly hexagon map, the evidence cards, adopt-a-maintainer and risk history.

## Akamai Cloud resources

| Resource | Label | Region | What it does |
|---|---|---|---|
| Linode, Nanode 1 GB, Ubuntu 24.04 | `sea-petr-web` | Seattle, `us-sea` | Runs the app on port 80 (`app.service`), and re-scans watched repos every night (`rescan.timer`) |
| Cloud Firewall | `sea-petr-fw` | | Drops all inbound traffic except ports 22 and 80 from the venue network |
| Managed PostgreSQL 18, 1 node | `sea-petr-db` | Seattle, `us-sea` | Scans, risk history, signals, watched repos, model cache, pgvector xz embeddings. The allow list holds only the Linode (IPv4 and IPv6) and our laptop |
| Object Storage bucket | `sea-petr-files` | Chicago, `us-ord` | Evidence archives, scan reports, the xz replay dataset. Its key works only on this bucket |
| Akamai Cloud Inference | | | `qwen3-8-27b` (tagging), `gemma-4-26b-a4b-it` (long mailing-list threads), `qwen3-embedding-8b` (xz similarity) |

## Run it on a laptop

You need [uv](https://docs.astral.sh/uv/) and, for a higher GitHub rate limit, the GitHub CLI signed in (`gh auth login`). Copy `.env.example` to `.env` and fill in the inference key, the `PG` lines and the `OBJ` lines.

```bash
uv run app.py              # the dashboard on http://localhost:8000
uv run app.py --replay     # print the xz replay month by month
uv run app.py --rescan     # re-scan watched repos (the nightly timer runs this)
```

## Deploy to the Linode

Add `SERVER_IP=<the Linode's IPv4>` to `.env`, then:

```bash
./deploy.sh
```

It copies the app, the replay dataset and the cache to the Linode, installs the app service and the nightly timer, restarts the app, and waits for `/health` to answer.

## Files

| File | What it is |
|---|---|
| `app.py` | The whole backend: dependency discovery, GitHub fetch, tagging, scoring, xz replay, API |
| `index.html` | The dashboard |
| `data/xz_replay.json` | 45 public xz-devel emails, 2021–2024, each quote checked against the archive |
| `data/xz_timeline.md` | The xz timeline with sources |
| `app.service`, `rescan.service`, `rescan.timer` | systemd units for the Linode |
| `deploy.sh` | Copies everything to the Linode, without the account token |

## Ground rules

Mithra reads public data only and never posts anywhere. A flag describes a situation, never a person: the people asking to help maintain a project are usually just that. The point is to know when a maintainer is stretched thin, and to help.

## Secrets

`.env` holds the inference key, the database password, the storage key and the account API token. It is in `.gitignore` and is never committed. `deploy.sh` sends the server a copy without the account API token or the root password, because the server faces the internet and never needs them.

## Clean up

Delete the Linode, the database, and the Object Storage bucket and key after the event. A stopped Linode still bills. Steps are in the workshop's [cleanup guide](https://github.com/akamai-developers/akamai-workshop-seattle-hackathon/blob/main/docs/cleanup.md).
