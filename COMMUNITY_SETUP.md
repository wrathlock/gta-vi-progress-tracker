# Community discussion setup

The GTA VI dashboard now contains a Community Discussion page and topic-specific discussions for PS5, Xbox, Game Files, Executable, Development Activity, and Evidence & Confidence.

## Required one-time owner action

1. Install the [utterances GitHub App](https://github.com/apps/utterances) for this repository (`wrathlock/gta-vi-progress-tracker`). Grant it access to the repository's **Issues**.
2. Keep GitHub Issues enabled in repository settings.
3. Open the [dashboard](https://wrathlock.github.io/gta-vi-progress-tracker/GTA_VI_Tracker/), choose **Community Discussion**, and create a test comment while signed in to GitHub.
4. Confirm that the comment appears in the repository's GitHub Issues and that the GitHub Actions workflow **Moderate community discussion** runs.
5. Review flagged/deleted comments in the Actions run logs and GitHub issue moderation tools. Enable GitHub notifications for new issues and comments to review borderline cases.

## Moderation boundaries

The `.github/workflows/moderate-community.yml` action applies basic automatic rules to discussion issue bodies and comments: executable-link distribution, repetitive URL spam, promotional spam, explicit threats, and oversized repetitive posts. Matched comments are removed; matched new discussion issues are closed and locked. GitHub platform abuse protection and human reporting remain necessary.

This is **not** comprehensive AI-based contextual moderation. It cannot reliably identify all hate speech, subtle harassment, misinformation, personal information, or context-dependent abuse. A stronger moderation service would require a secure server-side integration and moderation API; do not expose API keys in this static GitHub Pages site.

The comment engine is separate from the GTA VI evidence collector. Comments do not affect source credibility, confidence ratings, milestone status, or verified research.

The repository currently has GitHub Issues enabled, but GitHub Discussions disabled. The implementation intentionally uses Issues/utterances rather than GitHub Discussions/giscus so it can run on the existing repository after the app is installed.
