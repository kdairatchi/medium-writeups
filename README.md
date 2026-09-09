# Bug Bounty Writeups & Reports Library

Single repo for kdairatchi's local bug bounty writeups, disclosed reports, methodology notes, and Medium feed tracking.

## Start Here

- [Reports](reports/index.html) - disclosed report datasets from `/home/anon/bounty-reports-data`.
- [Writeups](writeups/index.html) - curated writeup lists and target/platform collections.
- [Medium/Methodology/Searchable Library](index.html) - the GitHub Pages view for the Medium feed, methodology notes, and manifest-backed search.
- [reports/INDEX.md](reports/INDEX.md) - source-by-source report inventory.
- [writeups/INDEX.md](writeups/INDEX.md) - source-by-source writeup inventory.
- [MANIFEST.json](MANIFEST.json) - machine-readable counts, byte totals, suffix breakdowns, and source mapping.

## Current Counts

- Report files mirrored: 2157
- Writeup files mirrored: 8
- Total files mirrored: 2165
- Generated: `2026-09-09T19:29:23.602459+00:00`

## Layout

```text
reports/
  google-vrp/
  h1/
  immunefi-boosts/
  immunefi-past-audits/
writeups/
  README.md
  INDEX.md
  medium-feed.md
  awesome/
  daily/
  facebook/
  methodology/
scripts/
  sync_library.py
```

## Refresh

```bash
# Rebuild indexes from the checked-in mirror.
python3 scripts/sync_library.py

# Refresh mirrored files from local corpora, then rebuild indexes.
python3 scripts/sync_library.py --copy
```

The GitHub Action writes the Medium feed to `writeups/medium-feed.md`, then regenerates this README and the category indexes from `MANIFEST.json`. It should never pipe feed output directly over the root README.

Do not delete the old source data until this repo has been reviewed, committed, pushed, and checked on GitHub.
