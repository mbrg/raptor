"""
GitHub Forensics Verifiable Evidence Schema

Two evidence types, same base pattern (when, who, what):

1. Event       - Something happened
                 when = when it happened
                 who = who did it
                 what = what they did
                 Sources: GH Archive, git log

2. Observation - Something we found
                 when = when we found it
                 who = who created it (optional)
                 what = what we found
                 Sources: GH Archive, GitHub API, Wayback, security blogs

IOC is a subtype of Observation.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl


# =============================================================================
# ENUMS
# =============================================================================


class EvidenceSource(str, Enum):
    """Where evidence was obtained from."""

    GHARCHIVE = "gharchive"
    GIT_LOG = "git_log"
    GITHUB_API = "github_api"
    GITHUB_WEB = "github_web"
    WAYBACK = "wayback"
    SECURITY_BLOG = "security_blog"


class EventType(str, Enum):
    """GitHub event types from GH Archive."""

    PUSH = "PushEvent"
    PULL_REQUEST = "PullRequestEvent"
    ISSUES = "IssuesEvent"
    ISSUE_COMMENT = "IssueCommentEvent"
    CREATE = "CreateEvent"
    DELETE = "DeleteEvent"
    FORK = "ForkEvent"
    WATCH = "WatchEvent"
    RELEASE = "ReleaseEvent"
    MEMBER = "MemberEvent"
    PUBLIC = "PublicEvent"
    WORKFLOW_RUN = "WorkflowRunEvent"


class RefType(str, Enum):
    BRANCH = "branch"
    TAG = "tag"
    REPOSITORY = "repository"


class PRAction(str, Enum):
    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    MERGED = "merged"


class IssueAction(str, Enum):
    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    DELETED = "deleted"


class WorkflowConclusion(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"


class IOCType(str, Enum):
    COMMIT_SHA = "commit_sha"
    FILE_PATH = "file_path"
    EMAIL = "email"
    USERNAME = "username"
    REPOSITORY = "repository"
    TAG_NAME = "tag_name"
    BRANCH_NAME = "branch_name"
    WORKFLOW_NAME = "workflow_name"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    API_KEY = "api_key"
    SECRET = "secret"
    URL = "url"
    OTHER = "other"


# =============================================================================
# COMMON MODELS
# =============================================================================


class GitHubActor(BaseModel):
    """GitHub user/actor."""

    login: str
    id: int | None = None
    is_bot: bool = False


class GitHubRepository(BaseModel):
    """GitHub repository reference."""

    owner: str
    name: str
    full_name: str
    id: int | None = None


class VerificationInfo(BaseModel):
    """How to verify this evidence."""

    source: EvidenceSource
    url: HttpUrl | None = None
    bigquery_table: str | None = None
    query: str | None = None


# =============================================================================
# BASE EVIDENCE - when, who, what
# =============================================================================


class Evidence(BaseModel):
    """
    Base evidence model.

    when - when it happened (event) or when found (observation)
    who  - who did it (event) or who created it (observation, optional)
    what - what happened (event) or what was found (observation)
    """

    evidence_id: str
    when: datetime
    who: GitHubActor | None = None
    what: str
    where: str | None = None  # Location (URL, path, repo)
    repository: GitHubRepository | None = None
    verification: VerificationInfo
    notes: str | None = None


# =============================================================================
# EVENT - Something that happened
# Sources: GH Archive, git log
# =============================================================================


class Event(Evidence):
    """Something that happened. who is required."""

    who: GitHubActor  # Required for events


class CommitInPush(BaseModel):
    """Commit embedded in PushEvent."""

    sha: str
    message: str
    author_name: str
    author_email: str


class PushEvent(Event):
    """Someone pushed commits."""

    event_type: Literal["push"] = "push"
    ref: str
    before_sha: str
    after_sha: str
    size: int
    commits: list[CommitInPush] = Field(default_factory=list)
    is_force_push: bool = False


class PullRequestEvent(Event):
    """PR action occurred."""

    event_type: Literal["pull_request"] = "pull_request"
    action: PRAction
    pr_number: int
    pr_title: str
    pr_body: str | None = None
    head_sha: str | None = None
    merged: bool = False


class IssueEvent(Event):
    """Issue action occurred."""

    event_type: Literal["issue"] = "issue"
    action: IssueAction
    issue_number: int
    issue_title: str
    issue_body: str | None = None
    labels: list[str] = Field(default_factory=list)


class IssueCommentEvent(Event):
    """Comment on issue/PR."""

    event_type: Literal["issue_comment"] = "issue_comment"
    action: Literal["created", "edited", "deleted"]
    issue_number: int
    comment_id: int
    comment_body: str


class CreateEvent(Event):
    """Branch/tag/repo created."""

    event_type: Literal["create"] = "create"
    ref_type: RefType
    ref_name: str


class DeleteEvent(Event):
    """Branch/tag deleted."""

    event_type: Literal["delete"] = "delete"
    ref_type: RefType
    ref_name: str


class ForkEvent(Event):
    """Repository forked."""

    event_type: Literal["fork"] = "fork"
    fork_full_name: str


class WorkflowRunEvent(Event):
    """GitHub Actions. Absence during commit = API attack."""

    event_type: Literal["workflow_run"] = "workflow_run"
    action: Literal["requested", "completed", "in_progress"]
    workflow_name: str
    head_sha: str
    conclusion: WorkflowConclusion | None = None


class ReleaseEvent(Event):
    """Release published."""

    event_type: Literal["release"] = "release"
    action: Literal["published", "created", "deleted"]
    tag_name: str
    release_name: str | None = None
    release_body: str | None = None


class WatchEvent(Event):
    """Repo starred (recon indicator)."""

    event_type: Literal["watch"] = "watch"


class MemberEvent(Event):
    """Collaborator added/removed."""

    event_type: Literal["member"] = "member"
    action: Literal["added", "removed"]
    member: GitHubActor


class PublicEvent(Event):
    """Repo made public."""

    event_type: Literal["public"] = "public"


AnyEvent = (
    PushEvent
    | PullRequestEvent
    | IssueEvent
    | IssueCommentEvent
    | CreateEvent
    | DeleteEvent
    | ForkEvent
    | WorkflowRunEvent
    | ReleaseEvent
    | WatchEvent
    | MemberEvent
    | PublicEvent
)


# =============================================================================
# OBSERVATION - Something we found
# Sources: GH Archive, GitHub API, Wayback, security blogs
# =============================================================================


class Observation(Evidence):
    """Something we found. who is optional (creator if known)."""

    found_by: EvidenceSource  # How we found it


# -----------------------------------------------------------------------------
# Commit observations
# -----------------------------------------------------------------------------


class CommitAuthor(BaseModel):
    name: str
    email: str
    date: datetime


class CommitFileChange(BaseModel):
    filename: str
    status: Literal["added", "modified", "removed", "renamed"]
    additions: int = 0
    deletions: int = 0
    patch: str | None = None


class CommitObservation(Observation):
    """Full commit details from API/web/git."""

    observation_type: Literal["commit"] = "commit"
    sha: Annotated[str, Field(min_length=40, max_length=40)]
    message: str
    author: CommitAuthor
    committer: CommitAuthor
    parents: list[str] = Field(default_factory=list)
    files: list[CommitFileChange] = Field(default_factory=list)
    is_dangling: bool = False


class ForcePushedCommitRef(Observation):
    """Reference to commit overwritten by force push."""

    observation_type: Literal["force_pushed_commit"] = "force_pushed_commit"
    deleted_sha: str
    replaced_by_sha: str
    branch: str
    pusher: GitHubActor
    recovered_commit: CommitObservation | None = None


# -----------------------------------------------------------------------------
# Wayback observations
# -----------------------------------------------------------------------------


class WaybackSnapshot(BaseModel):
    """Single Wayback capture."""

    timestamp: str
    captured_at: datetime
    archive_url: HttpUrl
    original_url: HttpUrl
    status_code: int = 200


class WaybackObservation(Observation):
    """Collection of Wayback snapshots for a URL."""

    observation_type: Literal["wayback"] = "wayback"
    original_url: HttpUrl
    snapshots: list[WaybackSnapshot]
    total_snapshots: int


class RecoveredIssue(Observation):
    """Issue/PR recovered from Wayback or GH Archive."""

    observation_type: Literal["recovered_issue"] = "recovered_issue"
    issue_number: int
    is_pull_request: bool = False
    title: str | None = None
    body: str | None = None
    state: Literal["open", "closed", "merged", "unknown"] | None = None
    source_snapshot: WaybackSnapshot | None = None


class RecoveredFile(Observation):
    """File content recovered from Wayback."""

    observation_type: Literal["recovered_file"] = "recovered_file"
    file_path: str
    content: str
    source_snapshot: WaybackSnapshot


class RecoveredWiki(Observation):
    """Wiki page recovered from Wayback."""

    observation_type: Literal["recovered_wiki"] = "recovered_wiki"
    page_name: str
    content: str
    source_snapshot: WaybackSnapshot


class RecoveredForks(Observation):
    """Fork list recovered from Wayback."""

    observation_type: Literal["recovered_forks"] = "recovered_forks"
    forks: list[str]
    source_snapshot: WaybackSnapshot


# -----------------------------------------------------------------------------
# IOC - Indicator of Compromise (subtype of Observation)
# -----------------------------------------------------------------------------


class IOC(Observation):
    """Indicator of Compromise."""

    observation_type: Literal["ioc"] = "ioc"
    ioc_type: IOCType
    value: str
    confidence: Literal["confirmed", "high", "medium", "low"] = "medium"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    extracted_from: str | None = None


AnyObservation = (
    CommitObservation
    | ForcePushedCommitRef
    | WaybackObservation
    | RecoveredIssue
    | RecoveredFile
    | RecoveredWiki
    | RecoveredForks
    | IOC
)


# =============================================================================
# INVESTIGATION CONTAINER
# =============================================================================


AnyEvidence = AnyEvent | AnyObservation


class TimelineEntry(BaseModel):
    """Single entry in investigation timeline."""

    timestamp: datetime
    evidence: AnyEvidence
    significance: Literal["critical", "high", "medium", "low", "info"] = "info"
    tags: list[str] = Field(default_factory=list)
    analysis: str | None = None


class ActorProfile(BaseModel):
    """Profile of an actor in investigation."""

    actor: GitHubActor
    first_seen: datetime
    last_seen: datetime
    repositories: list[str] = Field(default_factory=list)
    event_types: list[EventType] = Field(default_factory=list)
    is_automation: bool = False
    evidence_ids: list[str] = Field(default_factory=list)


class Investigation(BaseModel):
    """Complete investigation."""

    investigation_id: str
    title: str
    description: str
    created_at: datetime
    updated_at: datetime
    status: Literal["active", "completed", "archived"] = "active"

    # Scope
    target_repositories: list[GitHubRepository] = Field(default_factory=list)
    target_actors: list[str] = Field(default_factory=list)
    time_start: datetime | None = None
    time_end: datetime | None = None

    # Evidence
    events: list[AnyEvent] = Field(default_factory=list)
    observations: list[AnyObservation] = Field(default_factory=list)

    # Analysis
    timeline: list[TimelineEntry] = Field(default_factory=list)
    actors: list[ActorProfile] = Field(default_factory=list)
    findings: str | None = None
    recommendations: list[str] = Field(default_factory=list)
