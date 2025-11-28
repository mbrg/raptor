---
name: github-forensics-schema
description: Pydantic schema for GitHub forensic evidence. Base pattern (when, who, what) applied to Events and Observations. IOC is a subtype of Observation.
version: 2.1
author: mbrg
tags: [github, forensics, schema, pydantic, osint]
---

# GitHub Forensics Evidence Schema

Same base pattern, two contexts:

```
Evidence (base)
├── when   - timestamp
├── who    - actor (optional for observations)
├── what   - description
├── where  - location
└── verification

Event (extends Evidence)       Observation (extends Evidence)
├── when = when it happened    ├── when = when we found it
├── who = who did it (req)     ├── who = creator (optional)
├── what = what they did       ├── what = what we found
└── Sources: GH Archive,       ├── found_by = how we found it
             git log           └── Sources: GH Archive, API,
                                            Wayback, blogs
```

## Events (from GH Archive / git log)

| Type | What |
|------|------|
| `PushEvent` | Pushed commits (commits embedded here) |
| `PullRequestEvent` | PR opened/closed/merged |
| `IssueEvent` | Issue opened/closed |
| `IssueCommentEvent` | Comment on issue/PR |
| `CreateEvent` | Branch/tag/repo created |
| `DeleteEvent` | Branch/tag deleted |
| `ForkEvent` | Repo forked |
| `WorkflowRunEvent` | GitHub Actions (absence = API attack) |
| `ReleaseEvent` | Release published |
| `WatchEvent` | Repo starred |
| `MemberEvent` | Collaborator changed |
| `PublicEvent` | Repo made public |

## Observations (from API / Wayback / blogs)

| Type | What |
|------|------|
| `CommitObservation` | Full commit from API/web/git |
| `ForcePushedCommitRef` | Reference to overwritten commit |
| `WaybackObservation` | Wayback snapshots for URL |
| `RecoveredIssue` | Issue/PR from Wayback/GH Archive |
| `RecoveredFile` | File from Wayback |
| `RecoveredWiki` | Wiki from Wayback |
| `RecoveredForks` | Fork list from Wayback |
| `IOC` | Indicator of Compromise |

## Examples

### PushEvent

```python
PushEvent(
    evidence_id="push-001",
    when=datetime(2025, 7, 13, 20, 30),
    who=GitHubActor(login="attacker"),
    what="Force pushed to refs/heads/main",
    repository=GitHubRepository(owner="org", name="repo", full_name="org/repo"),
    verification=VerificationInfo(source=EvidenceSource.GHARCHIVE, ...),
    ref="refs/heads/main",
    before_sha="abc...",
    after_sha="def...",
    size=0,
    is_force_push=True
)
```

### CommitObservation

```python
CommitObservation(
    evidence_id="commit-001",
    when=datetime.utcnow(),  # When we found it
    who=GitHubActor(login="author"),  # Creator
    what="Malicious commit def456",
    where="https://github.com/org/repo/commit/def456...",
    found_by=EvidenceSource.GITHUB_API,
    verification=VerificationInfo(source=EvidenceSource.GITHUB_API, ...),
    sha="def456...",
    message="Add feature",
    author=CommitAuthor(...),
    committer=CommitAuthor(...),
    is_dangling=True  # Force-pushed over
)
```

### IOC

```python
IOC(
    evidence_id="ioc-001",
    when=datetime.utcnow(),
    what="Malicious commit SHA from security blog",
    where="https://security-blog.example.com/analysis",
    found_by=EvidenceSource.SECURITY_BLOG,
    verification=VerificationInfo(source=EvidenceSource.SECURITY_BLOG, ...),
    ioc_type=IOCType.COMMIT_SHA,
    value="678851bbe9776228f55e0460e66a6167ac2a1685",
    confidence="confirmed"
)
```

## Investigation

```python
Investigation(
    events=[...],        # Things that happened
    observations=[...],  # Things we found (including IOCs)
    timeline=[...],
    actors=[...],
    findings="..."
)
```

## Sources

| Source | Events | Observations |
|--------|--------|--------------|
| `GHARCHIVE` | ✓ | ✓ (deleted content) |
| `GIT_LOG` | ✓ | |
| `GITHUB_API` | | ✓ |
| `GITHUB_WEB` | | ✓ |
| `WAYBACK` | | ✓ |
| `SECURITY_BLOG` | | ✓ (IOCs) |
