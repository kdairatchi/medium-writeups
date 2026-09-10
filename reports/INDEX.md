# Reports Index

Mirrored disclosed report datasets for local research and pattern mining.

Generated: `2026-09-10T00:06:06.700528+00:00`

| Source | Files | Size | Types | Notes |
|---|---:|---:|---|---|
| [google-vrp](google-vrp/) | 2 | 171.0 KB | `.csv` 1, `.md` 1 | Google VRP report exports |
| [h1](h1/) | 85 | 4.3 MB | `.csv` 1, `.md` 83, `.txt` 1 | HackerOne disclosed report exports |
| [immunefi-boosts](immunefi-boosts/) | 1035 | 7.9 MB | `.md` 1035 | Immunefi boost reports |
| [immunefi-past-audits](immunefi-past-audits/) | 1035 | 7.9 MB | `.md` 1035 | Immunefi past audit reports |

## Usage

- Treat this repo as a searchable local corpus for bug patterns, not as a live target list.
- Start with titles and indexes, then open the original report/writeup for proof shape and kill conditions.
- Refresh with `python3 scripts/sync_library.py --copy` when the local source corpora change.
