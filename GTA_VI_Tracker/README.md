# GTA VI Signal Tracker V2.7 — Live Firefox edition

A standalone HTML dashboard (all 43 original V2.7 sections retained, 21 original sources and historical baseline untouched) with public GitHub activity collection and source availability telemetry.

## One-time setup

1. Create a **public** GitHub repository named `gta-vi-signal-tracker` on your GitHub account.
2. Upload **the contents** of this ZIP (not the ZIP itself) to the repository, including `.github/workflows/live.yml` and `.nojekyll`. Use GitHub web Upload files or `git push` from a computer. Some web uploads may omit hidden `.github` folder: confirm it exists.
3. In **Settings → Pages**, choose **GitHub Actions** as the publishing source.
4. In **Actions**, enable workflows if prompted, then run `GTA VI public research collector + Firefox dashboard` using **Run workflow**.
5. Open `https://YOUR-USERNAME.github.io/gta-vi-signal-tracker/` in Firefox. Leave the tab open for five-minute JSON refreshes; the hosted collector scans hourly independently of your browser.
6. If Pages is not available, check the repository visibility and workflow permissions. Under Settings → Actions → General → Workflow permissions, permit read/write if the automatic history commit is denied.

## Accuracy and privacy

- Scheduled at minute 17 of every hour (UTC), **best effort**. GitHub Actions schedules may run late or be skipped. Timestamps are from real script executions, not schedule expectations.
- GitHub API collects recent public commits, releases, issues, PRs, timestamps and metadata, grades all raw records C1, and **does not treat them as GTA VI breakthroughs**.
- Other sources get **reachability checks only**. Their content is **not** searched or independently verified. Wayfinder is not treated as evidence of executable availability.
- No executables, ROMs, binaries, pirated content, or suspicious downloads are collected.
- No GTA VI boot/gameplay/FPS is asserted or fabricated. Blank means unverified, not zero.
- Stored snapshots/history in `data/` are public in this repository. Never include private data or tokens.
- Existing ChatGPT hourly automations are separate and unchanged; this workflow never sends alerts.
- When opening `index.html` locally with Firefox (file://), the historic offline dashboard still works, while live fetches may be blocked. Use the published HTTPS site for automatic updates.
- In `index.html`, the static original V2.7 snapshot remains embedded to preserve old functionality and sections, while `live.js` adds new views fed only by `data/live.json`.

## Source coverage

The 21 original source URLs are represented in the collector; 10 GitHub repo sources get actual public activity collection, all other sources get availability checks only. Source reachability is not proof of reviewing the contents.

## Files

- `index.html`: original interactive V2.7 dashboard with Firefox live adapter
- `live.js`: optional live-data interface and auto refresh
- `baseline.json`: original V2.7 historical data
- `collector/collect.py`: stdlib public-source telemetry collector
- `.github/workflows/live.yml`: hourly collector + GitHub Pages deployment
- `data/live.json`, `data/history.json`, `data/snapshots/`: dated output
