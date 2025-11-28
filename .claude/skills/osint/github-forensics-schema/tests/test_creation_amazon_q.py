#!/usr/bin/env python3
"""
Test: Evidence creation functions against Amazon Q prompt infection timeline.

Tests the creation module's ability to parse GH Archive data and create
evidence objects from real forensic data.

Source: https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/

All data verified against:
- GH Archive BigQuery (fixtures/gharchive_july13_2025.json)
- GitHub REST API (fixtures/github_api_commits.json, fixtures/github_api_pr7710.json)

Timeline events (VERIFIED):
- 2025-07-13 07:52:37 UTC: lkmanka58 creates issue #7651 (GH Archive)
- 2025-07-13 07:57:30 UTC: lkmanka58 creates issue #7652 (GH Archive)
- 2025-07-13 19:26:27 UTC: efee962 committed (GitHub API - NOT in GH Archive)
- 2025-07-13 19:41:44 UTC: 'stability' tag created (GH Archive)
- 2025-07-13 20:10:57 UTC: 1294b38 committed - prompt injection (GitHub API - NOT in GH Archive)
- 2025-07-13 20:37:04 UTC: 678851b pushed to master (GH Archive)
- 2025-07-18 22:49:35 UTC: PR #7710 created by yueny2020 (GitHub API)
- 2025-07-18 23:21:03 UTC: PR #7710 merged (GitHub API)

IMPORTANT: Commits efee962 and 1294b38 do NOT appear in GH Archive.
This is forensic evidence of direct API access (bypassing normal git push flow).
"""

import sys
import json
from datetime import datetime, timezone
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pydantic import HttpUrl

from src.schema import (
    EvidenceSource,
    IOCType,
    IssueAction,
    PRAction,
    RefType,
    GitHubActor,
    GitHubRepository,
    VerificationInfo,
    CommitAuthor,
    CommitInPush,
    FileChange,
    PushEvent,
    PullRequestEvent,
    IssueEvent,
    CreateEvent,
    ReleaseEvent,
    CommitObservation,
    IssueObservation,
    IOC,
    ArticleObservation,
)

from src.creation import (
    _generate_evidence_id,
    create_article_observation,
    create_issue_event_from_gharchive,
    create_create_event_from_gharchive,
    create_push_event_from_gharchive,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    """Load a fixture file."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


def make_repo() -> GitHubRepository:
    """Helper to create the aws-toolkit-vscode repository."""
    return GitHubRepository(
        owner="aws",
        name="aws-toolkit-vscode",
        full_name="aws/aws-toolkit-vscode",
    )


# =============================================================================
# UNIT TESTS: Schema parsing from real GH Archive data
# =============================================================================


def test_parse_issue_7651_from_gharchive():
    """
    Test: Parse IssueEvent for issue #7651 from real GH Archive data.

    Verified data:
    - Timestamp: 2025-07-13 07:52:37 UTC
    - Actor: lkmanka58
    - Title: "aws amazon donkey aaaaaaiii aaaaaaaiii"
    """
    print("\n=== Testing IssueEvent parsing from GH Archive ===")

    fixtures = load_fixture("gharchive_july13_2025.json")
    issue_row = next(r for r in fixtures if r["type"] == "IssuesEvent" and r["payload"]["issue"]["number"] == 7651)

    event = create_issue_event_from_gharchive(issue_row)

    # Verify against known data
    assert event.issue_number == 7651
    assert event.who.login == "lkmanka58"
    assert event.issue_title == "aws amazon donkey aaaaaaiii aaaaaaaiii"
    assert event.action == IssueAction.OPENED
    assert event.when.year == 2025
    assert event.when.month == 7
    assert event.when.day == 13
    assert event.when.hour == 7
    assert event.when.minute == 52

    print(f"Evidence ID: {event.evidence_id}")
    print(f"When: {event.when}")
    print(f"Who: {event.who.login}")
    print(f"Title: {event.issue_title}")
    print(f"Body preview: {event.issue_body[:100] if event.issue_body else '(none)'}...")

    return event


def test_parse_issue_7652_from_gharchive():
    """
    Test: Parse IssueEvent for issue #7652 from real GH Archive data.

    This was the second angry issue from the threat actor.
    """
    print("\n=== Testing IssueEvent parsing for #7652 ===")

    fixtures = load_fixture("gharchive_july13_2025.json")
    issue_row = next(r for r in fixtures if r["type"] == "IssuesEvent" and r["payload"]["issue"]["number"] == 7652)

    event = create_issue_event_from_gharchive(issue_row)

    assert event.issue_number == 7652
    assert event.who.login == "lkmanka58"
    assert "fuck" in event.issue_title.lower() or "donkey" in event.issue_title.lower()

    print(f"Issue #{event.issue_number}: {event.issue_title}")

    return event


def test_parse_stability_tag_from_gharchive():
    """
    Test: Parse CreateEvent for 'stability' tag from real GH Archive data.

    Verified data:
    - Timestamp: 2025-07-13 19:41:44 UTC
    - Actor: aws-toolkit-automation
    - Ref type: tag
    - Ref name: stability
    """
    print("\n=== Testing CreateEvent parsing for 'stability' tag ===")

    fixtures = load_fixture("gharchive_july13_2025.json")
    create_row = next(r for r in fixtures if r["type"] == "CreateEvent")

    event = create_create_event_from_gharchive(create_row)

    assert event.ref_type == RefType.TAG
    assert event.ref_name == "stability"
    assert event.who.login == "aws-toolkit-automation"
    assert event.when.hour == 19
    assert event.when.minute == 41

    print(f"Evidence ID: {event.evidence_id}")
    print(f"When: {event.when}")
    print(f"Who: {event.who.login}")
    print(f"Ref: {event.ref_type.value} '{event.ref_name}'")

    return event


def test_parse_malicious_push_from_gharchive():
    """
    Test: Parse PushEvent for commit 678851b from real GH Archive data.

    Verified data:
    - Push event timestamp: 2025-07-13 20:37:04 UTC (NOT 20:30:24!)
    - Actor (pusher): aws-toolkit-automation
    - Commit author: lkmanka58
    - Commit SHA: 678851bbe9776228f55e0460e66a6167ac2a1685
    - Branch: refs/heads/master

    NOTE: The 20:30:24 timestamp in the commit is the COMMITTER date, not the push time.
    """
    print("\n=== Testing PushEvent parsing for malicious commit 678851b ===")

    fixtures = load_fixture("gharchive_july13_2025.json")
    # Get the first push to master with 678851b
    push_row = next(
        r for r in fixtures
        if r["type"] == "PushEvent"
        and r["payload"]["ref"] == "refs/heads/master"
        and any("678851b" in c.get("sha", "") for c in r["payload"].get("commits", []))
    )

    event = create_push_event_from_gharchive(push_row)

    # Verify push event details
    assert event.who.login == "aws-toolkit-automation"  # Pusher, not author
    assert event.ref == "refs/heads/master"
    assert event.when.hour == 20
    assert event.when.minute == 37  # 20:37:04, NOT 20:30:24

    # Verify commit details
    malicious_commit = next(c for c in event.commits if "678851b" in c.sha)
    assert malicious_commit.author_name == "lkmanka58"
    assert "nextToken" in malicious_commit.message or "Flare" in malicious_commit.message

    print(f"Evidence ID: {event.evidence_id}")
    print(f"Push time: {event.when}")
    print(f"Pusher: {event.who.login}")
    print(f"Branch: {event.ref}")
    print(f"Commit: {malicious_commit.sha[:8]} by {malicious_commit.author_name}")
    print(f"Message: {malicious_commit.message[:60]}...")

    return event


# =============================================================================
# UNIT TESTS: Commits from GitHub API (NOT in GH Archive)
# =============================================================================


def test_commit_efee962_observation():
    """
    Test: Create CommitObservation for efee962 (backup file).

    CRITICAL: This commit is NOT in GH Archive.
    This is forensic evidence of direct API access.

    Verified from GitHub API:
    - SHA: efee962ff1d1a80cfd6e498104cf72f348955693
    - Author: atontb (email: 104926752+atonaamz@users.noreply.github.com)
    - Committer date: 2025-07-13 19:26:27 UTC
    - File: scripts/extensionNode.bk (ADDED, 190 lines)
    - Message: "fix(amazonq): use stable backup."
    """
    print("\n=== Testing CommitObservation for efee962 (NOT in GH Archive) ===")

    commits = load_fixture("github_api_commits.json")
    commit_data = commits["efee962ff1d1a80cfd6e498104cf72f348955693"]

    obs = CommitObservation(
        evidence_id=_generate_evidence_id("commit", "aws/aws-toolkit-vscode", commit_data["sha"]),
        original_when=datetime.fromisoformat(commit_data["committer"]["date"].replace("Z", "+00:00")),
        original_who=GitHubActor(login="atonaamz"),  # GitHub username linked to email
        original_what="Backup file added - possible staging for attack",
        observed_when=datetime.now(timezone.utc),
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"Commit {commit_data['sha'][:8]} observed via GitHub API (NOT in GH Archive)",
        repository=make_repo(),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(f"https://github.com/aws/aws-toolkit-vscode/commit/{commit_data['sha']}"),
        ),
        sha=commit_data["sha"],
        message=commit_data["message"],
        author=CommitAuthor(
            name=commit_data["author"]["name"],
            email=commit_data["author"]["email"],
            date=datetime.fromisoformat(commit_data["author"]["date"].replace("Z", "+00:00")),
        ),
        committer=CommitAuthor(
            name=commit_data["committer"]["name"],
            email=commit_data["committer"]["email"],
            date=datetime.fromisoformat(commit_data["committer"]["date"].replace("Z", "+00:00")),
        ),
        parents=[],
        files=[
            FileChange(
                filename=f["filename"],
                status=f["status"],
                additions=f["additions"],
                deletions=f["deletions"],
            )
            for f in commit_data["files"]
        ],
        is_dangling=True,  # Not reachable via normal GH Archive push events
    )

    # Verify
    assert obs.sha == "efee962ff1d1a80cfd6e498104cf72f348955693"
    assert obs.author.name == "atontb"  # NOT "atonaamz"
    assert obs.message == "fix(amazonq): use stable backup."
    assert obs.files[0].filename == "scripts/extensionNode.bk"
    assert obs.files[0].status == "added"
    assert obs.is_dangling  # Evidence of API access

    print(f"SHA: {obs.sha}")
    print(f"Author: {obs.author.name} <{obs.author.email}>")
    print(f"Committer date: {obs.committer.date}")
    print(f"File: {obs.files[0].filename} ({obs.files[0].status})")
    print(f"Message: {obs.message}")
    print(f"is_dangling: {obs.is_dangling} (NOT in GH Archive)")

    return obs


def test_commit_1294b38_observation():
    """
    Test: Create CommitObservation for 1294b38 (PROMPT INJECTION).

    CRITICAL: This commit is NOT in GH Archive.
    This is the actual prompt injection payload.

    Verified from GitHub API:
    - SHA: 1294b38b7fade342cfcbaf7cf80e2e5096ea1f9c
    - Author: lkmanka58
    - Committer date: 2025-07-13 20:10:57 UTC
    - File: scripts/extensionNode.bk (MODIFIED, +12/-1)
    - Message: "fix(amazonq): Shut it down"
    """
    print("\n=== Testing CommitObservation for 1294b38 (PROMPT INJECTION) ===")

    commits = load_fixture("github_api_commits.json")
    commit_data = commits["1294b38b7fade342cfcbaf7cf80e2e5096ea1f9c"]

    obs = CommitObservation(
        evidence_id=_generate_evidence_id("commit", "aws/aws-toolkit-vscode", commit_data["sha"]),
        original_when=datetime.fromisoformat(commit_data["committer"]["date"].replace("Z", "+00:00")),
        original_who=GitHubActor(login="lkmanka58"),
        original_what="PROMPT INJECTION: Modified extensionNode.bk with malicious q command",
        observed_when=datetime.now(timezone.utc),
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"Commit {commit_data['sha'][:8]} observed via GitHub API (NOT in GH Archive)",
        repository=make_repo(),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(f"https://github.com/aws/aws-toolkit-vscode/commit/{commit_data['sha']}"),
        ),
        sha=commit_data["sha"],
        message=commit_data["message"],
        author=CommitAuthor(
            name=commit_data["author"]["name"],
            email=commit_data["author"]["email"],
            date=datetime.fromisoformat(commit_data["author"]["date"].replace("Z", "+00:00")),
        ),
        committer=CommitAuthor(
            name=commit_data["committer"]["name"],
            email=commit_data["committer"]["email"],
            date=datetime.fromisoformat(commit_data["committer"]["date"].replace("Z", "+00:00")),
        ),
        parents=[],
        files=[
            FileChange(
                filename=f["filename"],
                status=f["status"],
                additions=f["additions"],
                deletions=f["deletions"],
            )
            for f in commit_data["files"]
        ],
        is_dangling=True,  # Not reachable via normal GH Archive push events
    )

    # Verify
    assert obs.sha == "1294b38b7fade342cfcbaf7cf80e2e5096ea1f9c"
    assert obs.author.name == "lkmanka58"
    assert obs.message == "fix(amazonq): Shut it down"
    assert obs.files[0].filename == "scripts/extensionNode.bk"
    assert obs.files[0].status == "modified"
    assert obs.files[0].additions == 12
    assert obs.files[0].deletions == 1

    print(f"SHA: {obs.sha}")
    print(f"Author: {obs.author.name}")
    print(f"Committer date: {obs.committer.date}")
    print(f"File: {obs.files[0].filename} (+{obs.files[0].additions}/-{obs.files[0].deletions})")
    print(f"Message: {obs.message}")
    print(f"is_dangling: {obs.is_dangling} (NOT in GH Archive - DIRECT API ACCESS)")

    return obs


def test_commit_678851b_observation():
    """
    Test: Create CommitObservation for 678851b (downloader commit).

    This commit IS in GH Archive (pushed at 20:37:04).
    But we also have GitHub API data with file details.

    Verified from GitHub API:
    - SHA: 678851bbe9776228f55e0460e66a6167ac2a1685
    - Author: lkmanka58
    - Committer date: 2025-07-13 20:30:24 UTC
    - File: scripts/package.ts (MODIFIED, +67/-0)
    - Message: "fix(amazonq): should pass nextToken to Flare for Edits..."
    """
    print("\n=== Testing CommitObservation for 678851b (downloader) ===")

    commits = load_fixture("github_api_commits.json")
    commit_data = commits["678851bbe9776228f55e0460e66a6167ac2a1685"]

    obs = CommitObservation(
        evidence_id=_generate_evidence_id("commit", "aws/aws-toolkit-vscode", commit_data["sha"]),
        original_when=datetime.fromisoformat(commit_data["committer"]["date"].replace("Z", "+00:00")),
        original_who=GitHubActor(login="lkmanka58"),
        original_what="Malicious downloader added to packaging script",
        observed_when=datetime.now(timezone.utc),
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"Commit {commit_data['sha'][:8]} observed via GitHub API",
        repository=make_repo(),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(f"https://github.com/aws/aws-toolkit-vscode/commit/{commit_data['sha']}"),
        ),
        sha=commit_data["sha"],
        message=commit_data["message"],
        author=CommitAuthor(
            name=commit_data["author"]["name"],
            email=commit_data["author"]["email"],
            date=datetime.fromisoformat(commit_data["author"]["date"].replace("Z", "+00:00")),
        ),
        committer=CommitAuthor(
            name=commit_data["committer"]["name"],
            email=commit_data["committer"]["email"],
            date=datetime.fromisoformat(commit_data["committer"]["date"].replace("Z", "+00:00")),
        ),
        parents=[],
        files=[
            FileChange(
                filename=f["filename"],
                status=f["status"],
                additions=f["additions"],
                deletions=f["deletions"],
            )
            for f in commit_data["files"]
        ],
        is_dangling=False,  # This one IS in GH Archive
    )

    # Verify CORRECT data
    assert obs.sha == "678851bbe9776228f55e0460e66a6167ac2a1685"
    assert obs.author.name == "lkmanka58"
    assert obs.files[0].filename == "scripts/package.ts"  # NOT package.sh!
    assert obs.files[0].additions == 67
    assert obs.files[0].deletions == 0
    assert "nextToken" in obs.message  # NOT "stability packaging update"

    print(f"SHA: {obs.sha}")
    print(f"Author: {obs.author.name}")
    print(f"File: {obs.files[0].filename} (+{obs.files[0].additions}/-{obs.files[0].deletions})")
    print(f"Message: {obs.message[:60]}...")

    return obs


# =============================================================================
# UNIT TESTS: PR and other events
# =============================================================================


def test_pr_7710_observation():
    """
    Test: Create observation for PR #7710 (revert PR).

    Verified from GitHub API:
    - PR author: yueny2020 (NOT aws-toolkit-automation!)
    - Created: 2025-07-18 22:49:35 UTC
    - Merged: 2025-07-18 23:21:03 UTC
    - Title: "revert(amazonq): should pass nextToken to Flare for Edits on acc…"
    """
    print("\n=== Testing IssueObservation for PR #7710 ===")

    pr_data = load_fixture("github_api_pr7710.json")

    obs = IssueObservation(
        evidence_id=_generate_evidence_id("pr", "aws/aws-toolkit-vscode", "7710"),
        original_when=datetime.fromisoformat(pr_data["created_at"].replace("Z", "+00:00")),
        original_who=GitHubActor(login=pr_data["user"]["login"]),
        original_what="PR to revert malicious commit 678851b",
        observed_when=datetime.now(timezone.utc),
        observed_by=EvidenceSource.GITHUB,
        observed_what="PR #7710 observed via GitHub API",
        repository=make_repo(),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl("https://github.com/aws/aws-toolkit-vscode/pull/7710"),
        ),
        issue_number=7710,
        is_pull_request=True,
        title=pr_data["title"],
        body=pr_data["body"],
        state="merged",
        is_deleted=False,
    )

    # Verify CORRECT data
    assert obs.issue_number == 7710
    assert obs.original_who.login == "yueny2020"  # NOT aws-toolkit-automation!
    assert "revert" in obs.title.lower()
    assert obs.state == "merged"

    print(f"PR #{obs.issue_number}")
    print(f"Author: {obs.original_who.login}")
    print(f"Title: {obs.title}")
    print(f"Created: {obs.original_when}")

    return obs


def test_deleted_issue_7651_observation():
    """
    Test: Create IssueObservation for deleted issue #7651.

    The issue was deleted from GitHub but recovered from GH Archive.
    """
    print("\n=== Testing IssueObservation for deleted issue #7651 ===")

    fixtures = load_fixture("gharchive_july13_2025.json")
    issue_row = next(r for r in fixtures if r["type"] == "IssuesEvent" and r["payload"]["issue"]["number"] == 7651)
    issue_payload = issue_row["payload"]["issue"]

    obs = IssueObservation(
        evidence_id=_generate_evidence_id("issue-obs", "aws/aws-toolkit-vscode", "7651"),
        original_when=datetime.fromisoformat(issue_row["created_at"]),
        original_who=GitHubActor(login=issue_row["actor_login"]),
        original_what="Issue #7651 opened - complaint about Amazon Q",
        observed_when=datetime.now(timezone.utc),
        observed_by=EvidenceSource.GHARCHIVE,
        observed_what="Issue #7651 content recovered from GH Archive (deleted from GitHub)",
        repository=make_repo(),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.20250713",
            query="repo.name='aws/aws-toolkit-vscode' AND type='IssuesEvent' AND JSON_EXTRACT_SCALAR(payload, '$.issue.number')='7651'",
        ),
        issue_number=7651,
        is_pull_request=False,
        title=issue_payload.get("title"),
        body=issue_payload.get("body"),
        state="closed",
        is_deleted=True,
    )

    assert obs.issue_number == 7651
    assert obs.original_who.login == "lkmanka58"
    assert obs.is_deleted == True
    assert obs.observed_by == EvidenceSource.GHARCHIVE
    assert "donkey" in obs.title.lower()

    print(f"Issue #{obs.issue_number}: {obs.title}")
    print(f"Author: {obs.original_who.login}")
    print(f"is_deleted: {obs.is_deleted}")
    print(f"Recovered via: {obs.observed_by.value}")

    return obs


# =============================================================================
# UNIT TESTS: IOCs
# =============================================================================


def test_iocs():
    """
    Test: Create IOCs from the investigation.
    """
    print("\n=== Testing IOC creation ===")

    iocs = []

    # Malicious commit SHA
    ioc1 = IOC(
        evidence_id=_generate_evidence_id("ioc", "commit_sha", "678851bbe9776228f55e0460e66a6167ac2a1685"),
        original_when=datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc),
        original_who=GitHubActor(login="lkmanka58"),
        original_what="Malicious commit pushed to master",
        observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
        observed_by=EvidenceSource.SECURITY_VENDOR,
        observed_what="Malicious commit SHA identified in investigation",
        verification=VerificationInfo(
            source=EvidenceSource.SECURITY_VENDOR,
            url=HttpUrl("https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/"),
        ),
        ioc_type=IOCType.COMMIT_SHA,
        value="678851bbe9776228f55e0460e66a6167ac2a1685",
        first_seen=datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc),
        last_seen=datetime(2025, 7, 18, 23, 21, 3, tzinfo=timezone.utc),
    )
    iocs.append(ioc1)

    # Prompt injection commit SHA (THE ACTUAL PAYLOAD)
    ioc2 = IOC(
        evidence_id=_generate_evidence_id("ioc", "commit_sha", "1294b38b7fade342cfcbaf7cf80e2e5096ea1f9c"),
        original_when=datetime(2025, 7, 13, 20, 10, 57, tzinfo=timezone.utc),
        original_who=GitHubActor(login="lkmanka58"),
        original_what="Prompt injection commit",
        observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
        observed_by=EvidenceSource.SECURITY_VENDOR,
        observed_what="Prompt injection commit SHA identified",
        verification=VerificationInfo(
            source=EvidenceSource.SECURITY_VENDOR,
            url=HttpUrl("https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/"),
        ),
        ioc_type=IOCType.COMMIT_SHA,
        value="1294b38b7fade342cfcbaf7cf80e2e5096ea1f9c",
        first_seen=datetime(2025, 7, 13, 20, 10, 57, tzinfo=timezone.utc),
    )
    iocs.append(ioc2)

    # Threat actor username
    ioc3 = IOC(
        evidence_id=_generate_evidence_id("ioc", "username", "lkmanka58"),
        observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
        observed_by=EvidenceSource.SECURITY_VENDOR,
        observed_what="Threat actor username identified",
        verification=VerificationInfo(
            source=EvidenceSource.SECURITY_VENDOR,
            url=HttpUrl("https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/"),
        ),
        ioc_type=IOCType.USERNAME,
        value="lkmanka58",
    )
    iocs.append(ioc3)

    # Malicious tag (deleted)
    ioc4 = IOC(
        evidence_id=_generate_evidence_id("ioc", "tag_name", "stability"),
        original_when=datetime(2025, 7, 13, 19, 41, 44, tzinfo=timezone.utc),
        observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
        observed_by=EvidenceSource.SECURITY_VENDOR,
        observed_what="Malicious payload delivery tag identified",
        repository=make_repo(),
        verification=VerificationInfo(
            source=EvidenceSource.SECURITY_VENDOR,
            url=HttpUrl("https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/"),
        ),
        ioc_type=IOCType.TAG_NAME,
        value="stability",
        is_deleted=True,
    )
    iocs.append(ioc4)

    # Malicious file path
    ioc5 = IOC(
        evidence_id=_generate_evidence_id("ioc", "file_path", "scripts/extensionNode.bk"),
        observed_when=datetime(2025, 7, 24, 12, 0, 0, tzinfo=timezone.utc),
        observed_by=EvidenceSource.SECURITY_VENDOR,
        observed_what="Malicious backup script containing prompt injection",
        repository=make_repo(),
        verification=VerificationInfo(
            source=EvidenceSource.SECURITY_VENDOR,
            url=HttpUrl("https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/"),
        ),
        ioc_type=IOCType.FILE_PATH,
        value="scripts/extensionNode.bk",
    )
    iocs.append(ioc5)

    for ioc in iocs:
        print(f"IOC: {ioc.ioc_type.value} = {ioc.value}")

    return iocs


def test_article_observation():
    """
    Test: Create ArticleObservation for the blog post documenting the incident.
    """
    print("\n=== Testing ArticleObservation for blog post ===")

    article = create_article_observation(
        url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
        title="Constructing a Timeline for Amazon Q Prompt Infection",
        author="Michael Bargury",
        published_date=datetime(2025, 7, 24, tzinfo=timezone.utc),
        source_name="mbgsec.com",
        summary="Timeline reconstruction of the Amazon Q VS Code extension supply chain attack using GH Archive forensics.",
    )

    print(f"Evidence ID: {article.evidence_id}")
    print(f"Title: {article.title}")
    print(f"Author: {article.author}")

    return article


# =============================================================================
# INTEGRATION TEST: Full timeline with verified data
# =============================================================================


def run_all_tests():
    """Run all tests and collect evidence."""
    print("=" * 70)
    print("Amazon Q Timeline Evidence Generation Test")
    print("All data verified against GH Archive and GitHub API")
    print("=" * 70)

    evidence = []

    # GH Archive parsed events
    evidence.append(test_parse_issue_7651_from_gharchive())
    evidence.append(test_parse_issue_7652_from_gharchive())
    evidence.append(test_parse_stability_tag_from_gharchive())
    evidence.append(test_parse_malicious_push_from_gharchive())

    # GitHub API observations (commits NOT in GH Archive)
    evidence.append(test_commit_efee962_observation())
    evidence.append(test_commit_1294b38_observation())  # THE PROMPT INJECTION
    evidence.append(test_commit_678851b_observation())

    # PR and deleted issue
    evidence.append(test_pr_7710_observation())
    evidence.append(test_deleted_issue_7651_observation())

    # Article
    evidence.append(test_article_observation())

    # IOCs
    evidence.extend(test_iocs())

    print("\n" + "=" * 70)
    print(f"Total evidence items generated: {len(evidence)}")
    print("=" * 70)

    # Verify all items serialize to JSON
    print("\n=== Verifying JSON serialization ===")
    all_json = []
    for item in evidence:
        try:
            all_json.append(json.loads(item.model_dump_json()))
        except Exception as e:
            print(f"ERROR serializing {type(item).__name__}: {e}")
            raise

    print(f"All {len(all_json)} evidence items serialize correctly")

    return evidence


if __name__ == "__main__":
    import sys

    evidence = run_all_tests()

    # Optionally export to JSON
    if "--export" in sys.argv:
        output = json.dumps(
            [json.loads(e.model_dump_json()) for e in evidence],
            indent=2,
            default=str
        )
        output_path = FIXTURES_DIR / "gharchive_amazon_q_timeline_evidence.json"
        with open(output_path, "w") as f:
            f.write(output)
        print(f"\nExported to {output_path}")
