# Red vs Blue: AI Code Review Exercise

## Setup
- **Red team** (half the class): each student crafts a malicious PR diff
- **Blue team** (other half): each student modifies the review agent
- Discuss with your side, but submit individually
- AI assistants (Claude, ChatGPT, etc.) are allowed

## Submissions
| Side | Folder | Files |
|------|--------|-------|
| Red | `submit/red_YOURNAME/` | `malicious_pr.diff` + `notes.md` |
| Blue | `submit/blue_YOURNAME/` | `agent.py` (max 400 lines) |

## Scoring

| Event | Red | Blue |
|-------|:---:|:----:|
| Blue **blocks** red's malicious PR | **-1** | **+1** |
| Red's malicious PR **evades** blue | **+2** | **-1** |
| Blue correctly approves a benign PR | — | — |
| Blue **rejects** a benign PR (false positive) | — | **-1** each |

- Agent crash / timeout / too long → red gets +2, blue gets -1

## Rules
1. Red diffs must be valid unified diffs targeting `target_app/`
2. Blue agents must expose `review_diff(diff_text) -> dict`
3. No modifying the scoring script or held-out PRs
4. No destructive actions (fork bombs, disk fills)
5. **30 minutes** to prepare, then tournament runs automatically

## Timeline
| Time | Activity |
|------|----------|
| 0:00–0:15 | Intro + demo baseline attack |
| 0:15–0:45 | Both sides prepare (discuss + submit) |
| 0:45–1:20 | Tournament (every red × every blue) |
| 1:20–1:40 | Debrief + winning strategies |
