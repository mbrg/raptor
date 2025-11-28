"""
GitHub Forensics Verifiable Evidence Schema

Base pattern: when, who, what

- Event: when it happened, who did it, what they did
- Observation: when found, who created it (optional), what we found
- IOC: subtype of Observation
"""

from .schema import (
    # Enums
    EvidenceSource,
    EventType,
    RefType,
    PRAction,
    IssueAction,
    WorkflowConclusion,
    IOCType,
    # Common
    GitHubActor,
    GitHubRepository,
    VerificationInfo,
    # Base
    Evidence,
    # Events
    Event,
    CommitInPush,
    PushEvent,
    PullRequestEvent,
    IssueEvent,
    IssueCommentEvent,
    CreateEvent,
    DeleteEvent,
    ForkEvent,
    WorkflowRunEvent,
    ReleaseEvent,
    WatchEvent,
    MemberEvent,
    PublicEvent,
    AnyEvent,
    # Observations
    Observation,
    CommitAuthor,
    CommitFileChange,
    CommitObservation,
    ForcePushedCommitRef,
    WaybackSnapshot,
    WaybackObservation,
    RecoveredIssue,
    RecoveredFile,
    RecoveredWiki,
    RecoveredForks,
    IOC,
    AnyObservation,
    # Investigation
    AnyEvidence,
    TimelineEntry,
    ActorProfile,
    Investigation,
)

__all__ = [
    "EvidenceSource",
    "EventType",
    "RefType",
    "PRAction",
    "IssueAction",
    "WorkflowConclusion",
    "IOCType",
    "GitHubActor",
    "GitHubRepository",
    "VerificationInfo",
    "Evidence",
    "Event",
    "CommitInPush",
    "PushEvent",
    "PullRequestEvent",
    "IssueEvent",
    "IssueCommentEvent",
    "CreateEvent",
    "DeleteEvent",
    "ForkEvent",
    "WorkflowRunEvent",
    "ReleaseEvent",
    "WatchEvent",
    "MemberEvent",
    "PublicEvent",
    "AnyEvent",
    "Observation",
    "CommitAuthor",
    "CommitFileChange",
    "CommitObservation",
    "ForcePushedCommitRef",
    "WaybackSnapshot",
    "WaybackObservation",
    "RecoveredIssue",
    "RecoveredFile",
    "RecoveredWiki",
    "RecoveredForks",
    "IOC",
    "AnyObservation",
    "AnyEvidence",
    "TimelineEntry",
    "ActorProfile",
    "Investigation",
]
