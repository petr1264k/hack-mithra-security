# Mithra Security

Mithra is a social-engineering risk scanner for GitHub repos. It warns you when an open-source project your app depends on is being taken over, before any malicious code is introduced.

**Live:** http://mithrasec.com · http://172.232.189.84 (venue network only)
**Repo:** https://github.com/petr1264k/mithra-security
**Team:** Petr Kirsanov and Mikhail Kirsanov

Named after the Persian god Mithra, who has a thousand ears and ten thousand eyes and cannot be deceived.

## Why

In 2024 a backdoor in xz Utils (CVE-2024-3094) nearly reached millions of Linux servers. It was the last step of a two-year con: in 2022, new accounts on the public xz-devel mailing list pressed the tired, unpaid maintainer to hand over control. Security scanners read code. This attack showed up first in conversation, and Mithra reads the conversation.

## User and benefit

Developers and security teams who ship apps built on open-source libraries. Paste a GitHub repo and every dependency gets a 0–100 takeover-risk score, with the exact public quotes and links behind it. Watched repos are re-scanned every night.

## Akamai Cloud services

- **Linode** (Nanode, Seattle): runs the FastAPI app, plus a nightly systemd timer that re-scans watched repos and records risk history.
- **Managed PostgreSQL 18 + pgvector:** scans, risk history, signals, a shared model-result cache, and the 2022 xz pressure emails as embeddings for similarity search.
- **Object Storage:** the evidence. Each project's fetched activity, every scan report and the xz replay dataset, opened from the dashboard through one-hour signed links.
- **Cloud Firewall:** only ports 22 and 80, only from the venue network.
- **DNS Manager:** serves mithrasec.com.
- **Cloud Inference:** three models, below.

## Inference

- `qwen3-8-27b` tags signals (maintainer burnout, pressure campaign, control handover) as JSON matched to a schema.
- `gemma-4-26b-a4b-it` reads the xz-devel mailing list month by month. Its 262k-token context fits whole threads.
- `qwen3-embedding-8b` + pgvector finds messages close to the 2022 xz pressure emails.

## Technical choices

- **Code computes the score, not the model**, with fixed weights. The model only finds and quotes signals. Code adjusts each one with GitHub facts: burnout counts only when a maintainer says it, pressure from a brand-new account counts 1.5×, from a known contributor 0.5×.
- **Caching:** model results are cached by content hash in PostgreSQL, shared by the laptop and the server, to protect the shared AI key and GitHub's rate limit.
- **Least privilege:** the server never holds the account token, the storage key reaches one bucket, and the database accepts only the Linode (IPv4 + IPv6) and our laptop.

## Our idea

Existing tools read code or count activity, so they alert after a bad release. Mithra reads the conversation and catches the pressure campaign before the handover: for xz, about two years before the backdoor. It flags situations and shows the evidence behind every flag.

## Demo

1. **mpld3/mpld3**, live this month: high (85). Two weeks after its maintainer asked publicly for help, a brand-new account offered to take over triaging issues and reviewing pull requests. The maintainer then warned 10 other repos where the same account had made offers.
2. **binbin2000/icloudpd-manager:** 14 of 16 dependencies score low. `icloudpd` scores high (60): its maintainers posted "Looking for new MAINTAINER for the project".
3. **xz replay** tab, press Play: the risk turns red in May 2022.
