# Project name TBD

Built at **Build with Akamai Cloud: Seattle — AI Workshop & Buildathon**, November 20, 2026, GitHub Bellevue.

**Team:** Petr Kirsanov and Petr's dad.

Starts from the workshop demo app in [akamai-developers/akamai-workshop-seattle-hackathon](https://github.com/akamai-developers/akamai-workshop-seattle-hackathon).

## Submission

```text
User and task: [who needs this, and what they need to do]
Benefit: [why they would use the app]
Services: [what each service does, and why it fits]
Inference: [model, task, reason for choosing it, and how we checked it]
Technical choice: [a decision about speed, reliability, access, or growth]
Our idea: [what is different, and why it helps]
Demo: [input, steps, and result]
Known limits: [what does not work yet]
```

## Akamai Cloud resources

| Resource | Label | Region | What it does |
|---|---|---|---|
| Linode, Nanode 1 GB, Ubuntu 24.04 | `sea-petr-web` | Seattle, `us-sea` | Runs the app on port 80 as a systemd service |
| Cloud Firewall | `sea-petr-fw` | | Drops all inbound traffic except ports 22 and 80 from allowed addresses |
| Managed PostgreSQL 18, 1 node | `sea-petr-db` | Seattle, `us-sea` | Saves data that must survive a restart. Its allow list holds only the Linode and our laptop |
| Akamai Cloud Inference | | | `qwen3-8-27b` (chat), `gemma-4-26b-a4b-it` (images, long documents), `qwen3-embedding-8b` (embeddings) |

## Run it on a laptop

You need [uv](https://docs.astral.sh/uv/). Copy `.env.example` to `.env` and fill in the inference key and the `PG` lines.

```bash
uv run app.py
```

Open http://localhost:8000.

## Deploy to the Linode

Add `SERVER_IP=<the Linode's IPv4>` to `.env`, then:

```bash
./deploy.sh
```

It copies the app to the Linode, restarts it, and waits for `/health` to answer.

## Secrets

`.env` holds the inference key, the database password, and the account API token. It is in `.gitignore` and is never committed. `deploy.sh` sends the server a copy without the account API token or the root password, because the server faces the internet and never needs them.

## Clean up

Delete the Linode, the database, and any Object Storage buckets and keys after the event. A stopped Linode still bills. Steps are in the workshop's [cleanup guide](https://github.com/akamai-developers/akamai-workshop-seattle-hackathon/blob/main/docs/cleanup.md).
