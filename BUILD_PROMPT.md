# Build xz Radar at the Akamai buildathon: complete hand-off

You are helping me (Petr) build a hackathon project today, Friday Nov 20, 2026, at "Build with Akamai Cloud: Seattle — AI Workshop & Buildathon" (GitHub Bellevue). My teammate is my dad. **Submissions are due at 3:00 PM.** Judging starts at 3:00, top projects demo live at 4:00. Start building right away with sensible defaults; don't stall on questions. Explain things in plain language.

## The idea: xz Radar

**One line:** an AI that reads the conversations around the open-source code you depend on, and warns you when a project looks like it's being taken over, before any bad code exists.

**Why:** modern software runs on free libraries, often maintained by one exhausted volunteer. Attackers earn trust and pressure burned-out maintainers into handing over control. In 2024 this nearly backdoored millions of Linux servers via **xz Utils** (CVE-2024-3094). Security tools scan code. These attacks show up in conversations years earlier, and AI makes fake personas and spam cheaper, so it's getting worse.

**xz timeline (verify details against public sources before showing them):**
- The maintainer, Lasse Collin, was an unpaid volunteer who said publicly he had limited energy and long-term mental health issues.
- "Jia Tan" (GitHub `JiaT75`) started contributing helpful patches around late 2021.
- In 2022, accounts such as "Jigar Kumar" and "Dennis Ens" pressured Lasse on the public `xz-devel` mailing list about slow progress, pushing for a new maintainer. Lasse replied that Jia Tan might take a bigger role.
- Jia Tan became co-maintainer and took over releases.
- Feb–Mar 2024: versions 5.6.0 and 5.6.1 shipped a backdoor hidden in test files and build scripts.
- Mar 29, 2024: Andres Freund noticed SSH logins were about 500 ms slow and disclosed it.

**Prior art, to cite honestly:**
- Socket.dev alerts *after* a new author publishes (npm only, "New author" and "Unstable ownership" alerts).
- OpenSSF Scorecard and CHAOSS measure activity metrics.
- Datadog's internal BewAIre reviews code changes.
- The 2025 paper "Beneath the Mask" (arXiv 2508.13453) uses graph queries and says no one has automated detecting this social engineering yet.
- **Our difference:** AI reads the *conversations* and catches the pressure campaign *before* the handover, which for xz was two years earlier.
- **Ground rule:** flag situations, never accuse people. Show evidence quotes and links. Read only public data. Never post to GitHub or mailing lists.

## What the app does (MVP first)

1. **Scan.** The user pastes a GitHub repo URL. The app finds its dependencies by parsing `requirements.txt`, `pyproject.toml`, `package.json`, or a PEP 723 `# /// script` header.
2. **Resolve.** Map each package to its source repo via the PyPI JSON API (`https://pypi.org/pypi/<pkg>/json` → `project_urls`) or the npm registry (`https://registry.npmjs.org/<pkg>` → `repository`).
3. **Fetch.** For each dependency, pull ~12 months of public activity from the GitHub API: issues and PR comments, recent contributors, maintainer and permission changes, release authors. Use `gh auth token` (I'm logged in as `petr1264k`) for a 5000-requests-per-hour limit. Cache everything and don't refetch.
4. **Tag.** The AI tags warning signals, each with a quote, URL and date:
   - `maintainer_burnout` ("no time", "looking for help", "stepping back")
   - `pressure_campaign` (newer accounts demanding faster progress or a new maintainer)
   - `control_handover` (a newcomer with little history gets merge or release rights)
   - `xz_similarity` (messages semantically similar to the 2022 xz pressure emails, via embeddings)
5. **Score.** Risk is 0–100 per dependency, **computed by code from the tagged signals with fixed weights, not by the model.** This is a verification point for the judges. Show 🟢🟡🔴.
6. **UI.** A results table, then click a dependency to see its evidence quotes, links and a timeline.
7. **Replay mode (the demo centerpiece).** Load the xz-devel mailing list history (find the public archive, e.g. on mail-archive.com) for 2021–2024. A play button runs month by month while a risk meter climbs, and it must **turn red in 2022, two years before the backdoor.** If fetching the archive is slow, save the key threads as a JSON dataset in Object Storage.
8. **"Adopt a maintainer" (the ending).** For burned-out maintainers, show "this person is carrying your app alone," with their sponsor link (from `.github/FUNDING.yml` or GitHub Sponsors) and open "help wanted" issues. The Linux Foundation says well-supported maintainers are the primary defense.
9. **Nightly re-scan.** A systemd timer on the Linode re-checks saved projects and records risk history.
10. **Stretch: AI vs AI.** An attacker model generates *synthetic* pressure threads (kept local, never posted), the detector tries to catch them, and we report a catch rate.

## Models (Akamai Cloud Inference, OpenAI-compatible)

- Base URL: `https://api.akamai-inference.com/v1`, key in `.env` as `AKAMAI_API_KEY`. Event keys work with only these three models:
  - `qwen3-8-27b` (`CHAT_MODEL`): signal tagging as JSON, using `response_format={"type":"json_schema",...}` as in the workshop's `01-inference/json_output.py`. Check `finish_reason == "stop"`.
  - `gemma-4-26b-a4b-it` (`VISION_MODEL`): reading long threads (262k-token context).
  - `qwen3-embedding-8b` (`EMBEDDING_MODEL`): 4096-dimension embeddings for xz-similarity search in pgvector.
- No image generation, no audio. Cache model results by content hash so we don't burn the team quota.
- **Evaluation to show judges:**
  - the xz replay (known ground truth)
  - a few healthy projects that should score green
  - an input with no data, which should say "not enough data", not guess

## Infrastructure (all already created and working)

| Thing | Details |
|---|---|
| Akamai account | `petr1264`, $300 credit. **Ask me before creating new cloud resources** (auto mode blocked creating extra Linodes earlier) |
| Linode | `sea-petr-web`, id `111516132`, Seattle `us-sea`, Nanode 1 GB, Ubuntu 24.04. IPv4 `172.232.189.84`, IPv6 `2600:3c0a::2000:8dff:fe47:3860`. SSH: `ssh root@172.232.189.84` (key already set up). uv is at `/root/.local/bin/uv`, not on PATH for non-login ssh |
| App service | systemd unit `app` runs `/root/.local/bin/uv run /root/app.py` with `PORT=80`, `WorkingDirectory=/root`, and reads `/root/.env`. Logs: `journalctl -u app -n 30` |
| Firewall | `sea-petr-fw`, id `233296844`. Inbound DROP except TCP 22 and 80 from `4.53.158.54/32` (the venue Wi-Fi). The app is only reachable from the venue network |
| PostgreSQL | `sea-petr-db`, id `566182`, PostgreSQL 18, Seattle, 1 node. Allow list: venue IP, Linode IPv4 and Linode IPv6 (the IPv6 entry fixed a 5-second connect delay). Settings are the `PG*` variables in `.env`. pgvector pattern: workshop `03-database/vectors.py` |
| Object Storage | bucket `sea-petr-files`, Chicago `us-ord`, endpoint `https://us-ord-10.linodeobjects.com`. The key `sea-petr-files-key` is limited to read/write on this bucket only. Pattern: workshop `04-object-storage/storage.py` (keep `request_checksum_calculation="when_required"`) |
| Account API token | `LINODE_TOKEN` in `.env`, scopes: Linodes, Firewalls, VPCs, Databases, Object Storage, IPs. **Never send it to the server** |

## Code and repos

- **Project repo:** `~/experiments/xz-radar`, GitHub `petr1264k/akamai-buildathon` (private). It currently holds the workshop demo app as a base: `app.py` (FastAPI, PEP 723 header, run with `uv run app.py`), `index.html`, `app.service`, `cloud-init.yaml`, `deploy.sh`, and `README.md` with the judging template.
- **Deploy:** `./deploy.sh`. It reads `SERVER_IP` from `.env`, copies `.env` **without** `LINODE_TOKEN` and `LINODE_ROOT_PASS` to the server, copies `app.py`, `index.html` and `app.service`, restarts, and waits for `/health`. If you add files, update `deploy.sh` to copy them.
- **Workshop reference repo:** `~/akamai-workshop-seattle-hackathon`. Read its labs for working patterns (`01-inference/`, `03-database/`, `04-object-storage/`, `docs/judging.md`). An old copy of the demo app may be running on `localhost:8000` from that folder. Stop it with `lsof -ti tcp:8000 | xargs kill` if you need the port.
- **Secrets:** `.env` holds every key. It's gitignored. **Never print, commit or paste secret values.** Before every commit, check that no `.env` file is tracked and no key strings appear in tracked files.
- **Commits:** commit as we go with clear messages. Keep the repo private; I'll decide later whether to make it public.

## Judging (from the workshop's docs/judging.md)

- **40% other Akamai Cloud services:** services a feature depends on, why they fit, how they're connected. "A resource shown in Cloud Manager is not enough." Show the feature using it. More services don't automatically score higher.
- **20% inference:** a useful model task, why that model, how we checked its results, including an input it can't answer.
- **20% usefulness:** who needs it and why.
- **20% creativity:** what's different, and why that's better.
- **README must include:** user and task, benefit, services, inference, technical choice, our idea, demo, known limits.
- **Technical choices to mention:**
  - the server never holds the account token
  - the storage key is limited to one bucket
  - the database allow list (IPv4 plus IPv6, which fixed a 5-second delay)
  - code, not the model, computes the risk score
  - caching to protect the shared AI key

## Time plan (now is about 1:00 PM)

| By | Goal |
|---|---|
| 1:45 | End to end on the laptop: paste repo → dependencies → fetch → AI tags → scores → table |
| 2:15 | Replay mode working, deployed to the Linode with `./deploy.sh`, database and storage in use |
| 2:30 | **Code freeze.** Then "Adopt a maintainer" only if it's trivial, plus a 30-second backup screen recording |
| 2:45 | README template filled in, submitted (get the link from event staff) |

## Pitch (2 minutes)

1. **Thriller opening:** a two-year con, a burned-out volunteer, fake accounts, and a backdoor caught only because one engineer noticed logins were half a second slow. "We built the tool that would have caught it two years earlier."
2. **Live:** the xz replay turns red in 2022. Then scan the code in the room: the workshop app's dependencies, or Akamai's own open-source repos.
3. **How it's built:** Linode for the API and the nightly scanner, PostgreSQL with pgvector for threads, signals, embeddings and risk history, Object Storage for evidence archives and the replay dataset, and the three models.
4. **Ending:** "Adopt a maintainer." The fix is supporting people, not just raising alarms.
5. **If asked "doesn't Socket do this?":** "Socket alerts after a new person publishes. We alert during the pressure campaign, two years earlier for xz."
