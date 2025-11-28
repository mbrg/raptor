# GitHub Forensics Schema - Test Specification

This document defines the test cases and invariant properties that must always hold for the GitHub Forensics Schema module.

---

## 1. Core Invariants (Properties to Always Maintain)

### 1.1 Evidence ID Determinism
```
PROPERTY: Same inputs MUST produce the same evidence_id
```
- `_generate_evidence_id("push", "owner/repo", "abc123")` called twice → identical result
- Evidence IDs use SHA256 truncated to 12 hex chars
- Format: `{prefix}-{hash12}`

### 1.2 Pydantic Model Integrity
```
PROPERTY: All models must validate required fields and reject invalid data
```
- Missing required fields → `ValidationError`
- Invalid field types → `ValidationError`
- Models serialize to JSON and deserialize back to equal objects

### 1.3 Source Accuracy
```
PROPERTY: verification.source must match the actual data source used
```
- Events from GH Archive → `EvidenceSource.GHARCHIVE`
- Observations from GitHub API → `EvidenceSource.GITHUB`
- Observations from Wayback → `EvidenceSource.WAYBACK`
- Observations from git → `EvidenceSource.GIT`
- IOCs from vendors → `EvidenceSource.SECURITY_VENDOR`

### 1.4 Temporal Consistency
```
PROPERTY: observed_when >= original_when (when both are set)
```
- Cannot observe something before it happened
- `original_when` may be None for observations without known origin time

### 1.5 Event/Observation Type Literals
```
PROPERTY: event_type/observation_type literals must match class names
```
- `PushEvent.event_type == "push"`
- `CommitObservation.observation_type == "commit"`

---

## 2. Schema Models Test Cases

### 2.1 Enums

| Test Case | Input | Expected |
|-----------|-------|----------|
| `EvidenceSource` valid values | All 5 values | Accepts `gharchive`, `git`, `github`, `wayback`, `security_vendor` |
| `EventType` valid values | All 12 values | Matches GH Archive event type strings |
| `IOCType` valid values | All 15 values | Covers all indicator types |
| `RefType` valid values | 3 values | `branch`, `tag`, `repository` |
| Invalid enum value | `"invalid"` | Raises ValueError |

### 2.2 GitHubActor

| Test Case | Input | Expected |
|-----------|-------|----------|
| Minimal actor | `{"login": "user"}` | Valid, `id=None`, `is_bot=False` |
| Full actor | `{"login": "user", "id": 123, "is_bot": True}` | Valid with all fields |
| Bot detection (suffix) | `{"login": "dependabot[bot]"}` | Should detect as bot after creation |
| Bot detection (alt suffix) | `{"login": "renovate-bot"}` | Should detect as bot after creation |

### 2.3 GitHubRepository

| Test Case | Input | Expected |
|-----------|-------|----------|
| Minimal repo | `{"owner": "o", "name": "r", "full_name": "o/r"}` | Valid |
| Full repo | `+ id: 12345` | Valid with ID |
| Missing full_name | `{"owner": "o", "name": "r"}` | ValidationError |
| Inconsistent full_name | `full_name != "{owner}/{name}"` | Still valid (no validation) - document behavior |

### 2.4 VerificationInfo

| Test Case | Input | Expected |
|-----------|-------|----------|
| Source only | `{"source": "github"}` | Valid |
| With URL | `+ url: "https://github.com/..."` | Valid HttpUrl |
| With BigQuery | `+ bigquery_table: "githubarchive.day.20240101"` | Valid |
| Invalid URL | `url: "not-a-url"` | ValidationError |

### 2.5 Event Base Class

| Test Case | Property | Expected |
|-----------|----------|----------|
| Required fields | `evidence_id`, `when`, `who`, `what`, `repository`, `verification` | All required |
| Datetime type | `when` | Must be `datetime` object |

### 2.6 All 12 Event Types

For each event type, test:
- Construction with minimal required fields
- Construction with all optional fields
- Correct `event_type` literal value
- Type-specific field validation

| Event Type | Key Fields to Test |
|------------|-------------------|
| `PushEvent` | `ref`, `before_sha`, `after_sha`, `size`, `commits[]`, `is_force_push` |
| `PullRequestEvent` | `action` (PRAction enum), `pr_number`, `merged` |
| `IssueEvent` | `action` (IssueAction enum), `issue_number` |
| `IssueCommentEvent` | `action` (Literal), `comment_id`, `comment_body` |
| `CreateEvent` | `ref_type` (RefType enum), `ref_name` |
| `DeleteEvent` | `ref_type`, `ref_name` |
| `ForkEvent` | `fork_full_name` |
| `WorkflowRunEvent` | `action`, `workflow_name`, `head_sha`, `conclusion` |
| `ReleaseEvent` | `action`, `tag_name` |
| `WatchEvent` | (no extra fields) |
| `MemberEvent` | `action`, `member` (GitHubActor) |
| `PublicEvent` | (no extra fields) |

### 2.7 Observation Base Class

| Test Case | Property | Expected |
|-----------|----------|----------|
| Required fields | `evidence_id`, `observed_when`, `observed_by`, `observed_what`, `verification` | Required |
| Optional original | `original_when`, `original_who`, `original_what` | All optional |
| Default is_deleted | `is_deleted` | Defaults to `False` |

### 2.8 All 10 Observation Types

| Observation Type | Key Fields | Constraints |
|-----------------|------------|-------------|
| `CommitObservation` | `sha` | 40 chars exactly |
| `IssueObservation` | `issue_number`, `is_pull_request` | `number > 0` |
| `FileObservation` | `file_path`, `content`, `content_hash` | Path non-empty |
| `WikiObservation` | `page_name`, `content` | |
| `ForkObservation` | `fork_full_name`, `parent_full_name` | |
| `BranchObservation` | `branch_name`, `head_sha` | |
| `TagObservation` | `tag_name`, `target_sha` | |
| `ReleaseObservation` | `tag_name` | |
| `SnapshotObservation` | `original_url`, `snapshots[]`, `total_snapshots` | |
| `IOC` | `ioc_type`, `value`, `confidence` | Confidence is Literal |

### 2.9 CommitObservation SHA Constraint

| Test Case | Input | Expected |
|-----------|-------|----------|
| Valid 40-char SHA | `"a" * 40` | Valid |
| Short SHA (39 chars) | `"a" * 39` | ValidationError |
| Long SHA (41 chars) | `"a" * 41` | ValidationError |

---

## 3. Query Models Test Cases

### 3.1 RepositoryQuery Validation

| Test Case | owner | name | Expected |
|-----------|-------|------|----------|
| Valid minimal | `"a"` | `"b"` | Valid |
| Valid complex | `"my-org"` | `"my-repo.js"` | Valid |
| Single char owner | `"a"` | `"repo"` | Valid (special case) |
| Invalid start char | `"-org"` | `"repo"` | ValidationError |
| Invalid end char | `"org-"` | `"repo"` | ValidationError |
| Invalid chars | `"org@!"` | `"repo"` | ValidationError |
| Owner too long | `"a" * 40` | `"repo"` | ValidationError (max 39) |
| Name too long | `"org"` | `"a" * 101` | ValidationError (max 100) |
| Empty owner | `""` | `"repo"` | ValidationError |
| Empty name | `"org"` | `""` | ValidationError |

### 3.2 CommitQuery SHA Validation

| Test Case | SHA | Expected |
|-----------|-----|----------|
| Full SHA (40 chars) | `"abc123..."` (40 hex) | Valid |
| Short SHA (7 chars) | `"abc1234"` | Valid |
| Too short (6 chars) | `"abc123"` | ValidationError |
| Too long (41 chars) | 41 hex chars | ValidationError |
| Invalid chars | `"GHIJKL..."` | ValidationError (not hex) |
| Uppercase hex | `"ABCDEF..."` | Valid (normalized to lower) |

### 3.3 WaybackQuery Date Validation

| Test Case | Date Format | Expected |
|-----------|-------------|----------|
| Year only | `"2024"` | Valid |
| Year-month | `"202401"` | Valid |
| Year-month-day | `"20240115"` | Valid |
| Full timestamp | `"20240115143022"` | Valid |
| Invalid format | `"2024-01-15"` | ValidationError |
| Too short | `"202"` | ValidationError |
| Too long | `"202401151430220"` | ValidationError |
| Non-numeric | `"2024abc"` | ValidationError |

### 3.4 GHArchiveQuery Validation

| Test Case | repo | actor | Expected |
|-----------|------|-------|----------|
| Repo only | `RepositoryQuery(...)` | `None` | Valid |
| Actor only | `None` | `"username"` | Valid |
| Both | `RepositoryQuery(...)` | `"username"` | Valid |
| Neither | `None` | `None` | ValidationError |

### 3.5 GHArchiveQuery from_date Validation

| Test Case | from_date | Expected |
|-----------|-----------|----------|
| Valid YYYYMMDD | `"20240115"` | Valid |
| Invalid format | `"2024-01-15"` | ValidationError (pattern mismatch) |
| Wrong length | `"2024"` | ValidationError |

---

## 4. Helper Functions Test Cases

### 4.1 _generate_evidence_id

| Test Case | Inputs | Expected |
|-----------|--------|----------|
| Deterministic | Same inputs twice | Identical output |
| Different prefix | `("push", "a")` vs `("pr", "a")` | Different output |
| Different parts | `("push", "a")` vs `("push", "b")` | Different output |
| Format | Any inputs | `"{prefix}-{12 hex chars}"` |

### 4.2 _parse_datetime

| Test Case | Input | Expected |
|-----------|-------|----------|
| ISO format Z | `"2024-01-15T14:30:22Z"` | Valid datetime, UTC |
| ISO format +offset | `"2024-01-15T14:30:22+00:00"` | Valid datetime |
| Space format | `"2024-01-15 14:30:22 UTC"` | Valid datetime |
| Date only | `"2024-01-15 14:30:22"` | Valid datetime |
| Already datetime | `datetime(...)` | Returns unchanged |
| Invalid format | `"not-a-date"` | Raises ValueError |
| None input | `None` | Returns None |

### 4.3 _make_github_actor (Bot Detection)

| Test Case | Login | Expected is_bot |
|-----------|-------|-----------------|
| Regular user | `"octocat"` | `False` |
| Bot suffix [bot] | `"dependabot[bot]"` | `True` |
| Bot suffix -bot | `"renovate-bot"` | `True` |
| Contains bot | `"robotuser"` | `False` (not suffix) |

### 4.4 _make_github_repo

| Test Case | owner, name, id | Expected |
|-----------|-----------------|----------|
| Without ID | `"o", "r", None` | `full_name == "o/r"`, `id == None` |
| With ID | `"o", "r", 123` | `id == 123` |

---

## 5. Event Creation from GH Archive

### 5.1 create_push_event_from_gharchive

| Test Case | Payload | Expected |
|-----------|---------|----------|
| Normal push | `size: 3, commits: [...]` | `is_force_push=False` |
| Force push | `size: 0, before != 0*40` | `is_force_push=True` |
| First push | `size: 0, before == 0*40` | `is_force_push=False` |
| Commits list | `commits: [{sha, message, author}]` | Parses into `CommitInPush` |
| Evidence ID | Any | Based on repo + after_sha |

### 5.2 create_pull_request_event_from_gharchive

| Test Case | Payload | Expected |
|-----------|---------|----------|
| Opened | `action: "opened"` | `PRAction.OPENED` |
| Closed not merged | `action: "closed", merged: false` | `PRAction.CLOSED` |
| Merged | `action: "closed", merged: true` | `PRAction.MERGED` |
| Reopened | `action: "reopened"` | `PRAction.REOPENED` |

### 5.3 create_issue_event_from_gharchive

| Test Case | Payload | Expected |
|-----------|---------|----------|
| Opened | `action: "opened"` | `IssueAction.OPENED` |
| Closed | `action: "closed"` | `IssueAction.CLOSED` |
| Deleted | `action: "deleted"` | `IssueAction.DELETED` |
| Unknown action | `action: "unknown"` | Defaults to `OPENED` |

### 5.4 Dispatch Table (GHARCHIVE_EVENT_CREATORS)

| Test Case | Event Type | Expected Creator |
|-----------|-----------|------------------|
| All 12 types | Each `EventType` value | Correct creator function |
| Unknown type | `"UnknownEvent"` | `create_event_from_gharchive` raises ValueError |

### 5.5 Common Properties Across All Event Creators

```
PROPERTY: All event creators must:
1. Parse payload from string or dict
2. Split repo_name into owner/name
3. Generate deterministic evidence_id
4. Set verification.source = GHARCHIVE
5. Parse created_at into datetime
6. Create GitHubActor with bot detection
```

---

## 6. Observation Creation Test Cases

### 6.1 From GitHub API

#### create_commit_observation

| Test Case | API Response | Expected |
|-----------|--------------|----------|
| Full response | All fields present | Complete observation |
| File changes | `files: [...]` | Parses into `FileChange` |
| Parent commits | `parents: [{sha}]` | List of SHA strings |
| Evidence ID | Any | Based on repo + sha |

#### create_issue_observation

| Test Case | API Response | Expected |
|-----------|--------------|----------|
| Issue | `is_pull_request=False` | Calls `get_issue` |
| PR | `is_pull_request=True` | Calls `get_pull_request` |
| Merged PR | `merged: true` | `state == "merged"` |
| Open issue | `state: "open"` | `state == "open"` |

#### create_file_observation

| Test Case | API Response | Expected |
|-----------|--------------|----------|
| Base64 content | `content: base64(...)` | Decoded correctly |
| Content hash | Any content | SHA256 of decoded content |
| Empty file | `content: ""` | Empty string, valid hash |

### 6.2 From GH Archive (Recovery)

#### create_issue_observation_from_gharchive

| Test Case | Query | Expected |
|-----------|-------|----------|
| Found at timestamp | Matching timestamp | Returns observation, `is_deleted=True` |
| Not found | No matching timestamp | Raises ValueError |
| Timestamp match | `timestamp in row_ts` | Must contain exact timestamp |

#### create_pr_observation_from_gharchive

| Test Case | Query | Expected |
|-----------|-------|----------|
| Merged PR | `merged: true` | `state == "merged"` |
| Open PR | `merged: false, state: "open"` | `state == "open"` |

#### create_commit_observation_from_gharchive

| Test Case | Query | Expected |
|-----------|-------|----------|
| SHA prefix match | Short SHA | Matches if prefix |
| Full SHA match | Full 40 chars | Exact match |
| Not found | No matching commit | Raises ValueError |

#### create_force_push_observation_from_gharchive

| Test Case | Payload | Expected |
|-----------|---------|----------|
| Force push detected | `size=0, before!=0*40` | Returns observation |
| Not force push | `size>0` | Raises ValueError |
| Initial push | `before==0*40` | Raises ValueError |

### 6.3 From Wayback

#### create_snapshot_observation

| Test Case | CDX Response | Expected |
|-----------|--------------|----------|
| Multiple snapshots | `[header, row1, row2]` | List of WaybackSnapshot |
| Empty response | `[]` or `[header]` | Empty snapshots list |
| Timestamp parsing | `"20240115143022"` | Correct datetime |

### 6.4 IOC Creation

#### create_ioc

| Test Case | Source URL Content | Expected |
|-----------|-------------------|----------|
| Value found | Contains IOC value | Returns IOC with `confidence="confirmed"` |
| Value not found | Missing IOC value | Raises ValueError |
| Fetch failed | HTTP error | Raises ValueError |
| Case insensitive | Different case match | Still valid |

---

## 7. Source Client Test Cases

### 7.1 GitHubClient

| Test Case | Method | Expected |
|-----------|--------|----------|
| Lazy session | First request | Creates session |
| Accept header | Any request | `application/vnd.github+json` |
| HTTP error | 404 response | Raises HTTPError |
| All endpoints | `get_*` methods | Correct URL construction |

### 7.2 WaybackClient

| Test Case | Method | Expected |
|-----------|--------|----------|
| CDX query params | `search_cdx(from_date, to_date)` | Correct params |
| Empty results | No snapshots | Returns `[]` |
| JSON parsing | CDX response | Header row skipped |

### 7.3 GHArchiveClient

| Test Case | Method | Expected |
|-----------|--------|----------|
| Table reference | Single day | `githubarchive.day.YYYYMMDD` |
| Table reference | Date range | `githubarchive.day.YYYYMM*` |
| Credentials | Path provided | Uses service account |
| No credentials | None | Default credentials |

### 7.4 GitClient

| Test Case | Method | Expected |
|-----------|--------|----------|
| Get commit | Valid SHA | Parses format string correctly |
| Get commit files | Valid SHA | Status mapped correctly |
| Subprocess error | Invalid SHA | Raises CalledProcessError |

---

## 8. EvidenceFactory Test Cases

### 8.1 Lazy Client Initialization

| Test Case | Action | Expected |
|-----------|--------|----------|
| Initial state | Constructor | All clients `None` |
| First github access | `.github` | Creates GitHubClient |
| Second github access | `.github` | Returns same instance |
| First wayback access | `.wayback` | Creates WaybackClient |
| GHArchive with creds | Constructor + `.gharchive` | Uses provided credentials |

### 8.2 Convenience Methods

| Method | Creates | Underlying Function |
|--------|---------|---------------------|
| `.commit()` | CommitQuery | `create_commit_observation` |
| `.issue()` | IssueQuery | `create_issue_observation` |
| `.pull_request()` | IssueQuery (is_pr=True) | `create_issue_observation` |
| `.file()` | FileQuery | `create_file_observation` |
| `.branch()` | BranchQuery | `create_branch_observation` |
| `.tag()` | TagQuery | `create_tag_observation` |
| `.release()` | ReleaseQuery | `create_release_observation` |
| `.forks()` | ForkQuery | `create_fork_observations` |
| `.wayback_snapshots()` | WaybackQuery | `create_snapshot_observation` |
| `.events_from_gharchive()` | GHArchiveQuery | `create_event_from_gharchive` |
| `.ioc()` | - | `create_ioc` |

### 8.3 Recovery Methods

| Method | Requires |
|--------|----------|
| `.recover_issue()` | Exact timestamp |
| `.recover_pr()` | Exact timestamp |
| `.recover_commit()` | Exact timestamp + SHA |
| `.recover_force_push()` | Exact timestamp |

---

## 9. Integration Properties

### 9.1 Round-Trip Serialization

```
PROPERTY: All models must serialize to JSON and back without data loss
```
```python
model = PushEvent(...)
json_str = model.model_dump_json()
restored = PushEvent.model_validate_json(json_str)
assert model == restored
```

### 9.2 Type Union Discrimination

```
PROPERTY: AnyEvent and AnyObservation unions must discriminate correctly
```
- Each event/observation has unique `event_type`/`observation_type`
- Type adapter can reconstruct correct type from JSON

### 9.3 Content Hash Consistency

```
PROPERTY: FileObservation.content_hash must be SHA256 of content
```
```python
import hashlib
obs = create_file_observation(...)
expected = hashlib.sha256(obs.content.encode()).hexdigest()
assert obs.content_hash == expected
```

### 9.4 is_deleted Flag Correctness

```
PROPERTY: Recovered content must have is_deleted=True
```
- `create_*_observation_from_gharchive` → `is_deleted=True`
- Current GitHub API observations → `is_deleted=False`

---

## 10. Error Handling Test Cases

| Scenario | Function | Expected Error |
|----------|----------|----------------|
| Invalid repo format | `RepositoryQuery` | `ValidationError` |
| Invalid SHA | `CommitQuery` | `ValidationError` |
| Missing repo AND actor | `GHArchiveQuery` | `ValidationError` |
| IOC not in source | `create_ioc` | `ValueError` |
| Issue not found | `create_issue_observation_from_gharchive` | `ValueError` |
| Commit not found | `create_commit_observation_from_gharchive` | `ValueError` |
| Force push not found | `create_force_push_observation_from_gharchive` | `ValueError` |
| Unknown event type | `create_event_from_gharchive` | `ValueError` |
| HTTP 404 | GitHubClient.get_* | `HTTPError` |
| Git command fails | GitClient._run | `CalledProcessError` |

---

## 11. Edge Cases

### 11.1 Empty/Null Handling

| Field | Empty/None Input | Expected |
|-------|------------------|----------|
| `commits` in PushEvent | `[]` | Valid, empty list |
| `files` in CommitObservation | `[]` | Valid, empty list |
| `parents` in CommitObservation | `[]` | Valid, empty list |
| `pr_body` in PullRequestEvent | `None` | Valid, optional |
| `original_*` in Observation | `None` | Valid, optional |

### 11.2 Unicode Handling

| Scenario | Input | Expected |
|----------|-------|----------|
| Commit message | Unicode chars | Preserved correctly |
| File content | UTF-8 encoded | Decoded correctly |
| Author name | Non-ASCII | Preserved correctly |

### 11.3 Large Payloads

| Scenario | Size | Expected |
|----------|------|----------|
| Many commits in push | 1000 commits | All parsed |
| Large file content | 1MB | Content hash still computed |
| Many snapshots | 1000 Wayback results | All converted |

---

## 12. Test Implementation Notes

### Fixtures Required

1. **Sample GH Archive rows** - Dict format matching BigQuery output
2. **Mock GitHub API responses** - JSON matching API structure
3. **Mock Wayback CDX responses** - JSON array format
4. **Sample git command output** - Format string output

### Mock Strategy

- GitHubClient: Mock `requests.Session.get`
- WaybackClient: Mock `requests.Session.get`
- GHArchiveClient: Mock `bigquery.Client.query`
- GitClient: Mock `subprocess.run`

### Test Categories

1. **Unit tests** - Each function in isolation
2. **Integration tests** - EvidenceFactory with mocked clients
3. **Property tests** - Hypothesis for invariant checking
4. **Validation tests** - Pydantic model validation

---

## 13. Coverage Requirements

| Module | Target Coverage |
|--------|-----------------|
| `schema.py` | 100% (all models) |
| `creation.py` | 95%+ (all paths) |
| Query validation | 100% |
| Error paths | 100% |
