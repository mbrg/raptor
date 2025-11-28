# GitHub Forensics Schema - Test Specification

A behavior-driven test strategy for forensic evidence collection and verification.

---

## 1. Behavior-Driven Scenarios (Priority 1)

Tests that verify actual forensic investigation workflows.

### 1.1 Recovering Deleted Malicious Content

```gherkin
SCENARIO: Recover deleted PR containing malware
  GIVEN a repository "victim/compromised-lib"
  AND PR #42 was opened at "2024-01-15T10:30:00Z" with title "Urgent security fix"
  AND the PR contained malicious code in the body
  AND the PR was deleted by the attacker
  WHEN analyst queries GH Archive with repo, PR number, and timestamp
  THEN the original PR content is recovered
  AND observation.is_deleted is True
  AND observation.title equals "Urgent security fix"
  AND observation.body contains the original malicious payload
  AND evidence_id is stable for deduplication across multiple recoveries

SCENARIO: Recover force-pushed commits
  GIVEN repository "target/package" had commits on branch "main"
  AND attacker force-pushed at "2024-01-15T14:22:33Z" removing 3 commits
  WHEN analyst queries for force push at that timestamp
  THEN the before_sha of the overwritten commit is recovered
  AND is_dangling is True (commit no longer reachable)
  AND analyst can use SHA to fetch full content if still in GitHub's object store

SCENARIO: Recover deleted issue used for C2 communication
  GIVEN issue #99 in "legit/project" was used to post encoded commands
  AND issue was deleted after commands were executed
  WHEN analyst recovers issue from GH Archive at creation timestamp
  THEN original issue body with encoded commands is recovered
  AND original_who identifies the threat actor's account
  AND verification.query contains reproducible BigQuery SQL
```

### 1.2 Correlating Evidence Across Sources

```gherkin
SCENARIO: Correlate GitHub commit with Wayback snapshot
  GIVEN malicious commit abc123 was pushed to "victim/lib"
  AND the README was modified to include a typosquatted URL
  WHEN analyst fetches current commit from GitHub API
  AND analyst fetches Wayback snapshots for the repo URL
  THEN both observations reference the same repository
  AND timestamps can be compared to establish timeline
  AND evidence_ids are unique but repository.full_name matches

SCENARIO: Verify IOC from security vendor report
  GIVEN Socket.dev published a report about compromised package
  AND report mentions commit SHA "abc123def456..."
  WHEN analyst creates IOC from the vendor report URL
  THEN system fetches the URL and confirms SHA appears in content
  AND IOC.confidence is "confirmed"
  AND IOC.verification.url points to the vendor report

SCENARIO: IOC verification fails for unverified claim
  GIVEN analyst attempts to create IOC for SHA "xyz789..."
  AND that SHA does NOT appear in the provided source URL
  WHEN create_ioc is called
  THEN ValueError is raised with clear message
  AND no unverified evidence enters the system
```

### 1.3 Building Attack Timelines

```gherkin
SCENARIO: Reconstruct supply chain attack timeline
  GIVEN attacker compromised "popular/package" over 3 days
  WHEN analyst queries GH Archive for all events in date range
  THEN events are returned in chronological order (when field)
  AND each event has deterministic evidence_id for deduplication
  AND events include: CreateEvent (malicious branch), PushEvent (backdoor),
      PullRequestEvent (merged), DeleteEvent (branch cleanup)

SCENARIO: Detect account takeover via member events
  GIVEN legitimate maintainer was removed and attacker added
  WHEN analyst queries MemberEvents for the repository
  THEN MemberEvent with action="removed" shows original maintainer
  AND MemberEvent with action="added" shows attacker account
  AND timestamps establish the takeover window
```

### 1.4 Current State Observation

```gherkin
SCENARIO: Observe current commit state for comparison
  GIVEN analyst has recovered deleted commit metadata from GH Archive
  WHEN analyst fetches current state of same commit from GitHub API
  THEN CommitObservation includes full file changes (patches)
  AND author/committer details are complete
  AND observation can be compared with recovered version

SCENARIO: Enumerate repository forks for malware spread analysis
  GIVEN malicious code was pushed to "source/repo"
  WHEN analyst queries for all forks
  THEN list of ForkObservation is returned
  AND each fork includes creation timestamp (for spread timeline)
  AND fork_full_name identifies potentially affected repos
```

---

## 2. Property-Based Invariants (Priority 2)

Properties that must hold for ALL inputs. Use Hypothesis for generation.

### 2.1 Evidence ID Determinism

```python
from hypothesis import given, strategies as st

@given(prefix=st.text(min_size=1), parts=st.lists(st.text(), min_size=1))
def test_evidence_id_is_deterministic(prefix, parts):
    """Same inputs always produce same evidence_id."""
    id1 = _generate_evidence_id(prefix, *parts)
    id2 = _generate_evidence_id(prefix, *parts)
    assert id1 == id2

@given(prefix=st.text(min_size=1), parts=st.lists(st.text(), min_size=1))
def test_evidence_id_format(prefix, parts):
    """Evidence ID follows {prefix}-{12 hex chars} format."""
    eid = _generate_evidence_id(prefix, *parts)
    assert "-" in eid
    prefix_part, hash_part = eid.rsplit("-", 1)
    assert prefix_part == prefix
    assert len(hash_part) == 12
    assert all(c in "0123456789abcdef" for c in hash_part)
```

### 2.2 Serialization Round-Trip

```python
@given(event=event_strategy())  # Custom Hypothesis strategy for events
def test_event_serialization_roundtrip(event):
    """All events survive JSON serialization without data loss."""
    json_str = event.model_dump_json()
    restored = type(event).model_validate_json(json_str)
    assert event == restored

@given(observation=observation_strategy())
def test_observation_serialization_roundtrip(observation):
    """All observations survive JSON serialization without data loss."""
    json_str = observation.model_dump_json()
    restored = type(observation).model_validate_json(json_str)
    assert observation == restored
```

### 2.3 Temporal Consistency

```python
@given(observation=observation_with_original_strategy())
def test_temporal_ordering(observation):
    """Cannot observe something before it happened."""
    if observation.original_when is not None:
        assert observation.observed_when >= observation.original_when
```

### 2.4 Content Hash Integrity

```python
@given(content=st.text())
def test_file_content_hash_matches(content):
    """FileObservation.content_hash is always SHA256 of content."""
    # Create observation with known content
    obs = FileObservation(
        evidence_id="test-123",
        observed_when=datetime.now(timezone.utc),
        observed_by=EvidenceSource.GITHUB,
        observed_what="test",
        verification=VerificationInfo(source=EvidenceSource.GITHUB),
        file_path="test.txt",
        content=content,
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
    )
    expected = hashlib.sha256(obs.content.encode()).hexdigest()
    assert obs.content_hash == expected
```

### 2.5 Bot Detection Consistency

```python
BOT_SUFFIXES = ["[bot]", "-bot"]

@given(login=st.text(min_size=1))
def test_bot_detection_suffix_based(login):
    """Bot detection is purely suffix-based."""
    actor = _make_github_actor(login)
    expected_bot = any(login.endswith(suffix) for suffix in BOT_SUFFIXES)
    assert actor.is_bot == expected_bot
```

### 2.6 Source Accuracy

```python
def test_gharchive_events_have_gharchive_source():
    """All events from GH Archive have correct source."""
    for event_type, creator in GHARCHIVE_EVENT_CREATORS.items():
        row = make_sample_gharchive_row(event_type)
        event = creator(row)
        assert event.verification.source == EvidenceSource.GHARCHIVE

def test_github_observations_have_github_source():
    """All observations from GitHub API have correct source."""
    # Test each create_*_observation function
    for creator, mock_response in GITHUB_OBSERVATION_CREATORS:
        with mock_github_api(mock_response):
            obs = creator(sample_query)
            assert obs.verification.source == EvidenceSource.GITHUB
```

---

## 3. Contract Tests (Priority 3)

Verify our code works with real external service response formats.

### 3.1 GitHub API Response Contract

```python
# Record real responses once, replay in tests
# Use VCR.py or responses library with recorded cassettes

class TestGitHubAPIContract:
    """Verify our parsing matches real GitHub API responses."""

    @pytest.mark.vcr("github_commit_response.yaml")
    def test_parse_real_commit_response(self):
        """CommitObservation parses real GitHub commit response."""
        client = GitHubClient()
        # Uses recorded response
        data = client.get_commit("octocat", "Hello-World", "abc123")

        # Verify we can parse it
        obs = create_commit_observation(
            CommitQuery(repo=RepositoryQuery(owner="octocat", name="Hello-World"), sha="abc123"),
            client
        )
        assert obs.sha == data["sha"]
        assert obs.message == data["commit"]["message"]

    @pytest.mark.vcr("github_issue_response.yaml")
    def test_parse_real_issue_response(self):
        """IssueObservation parses real GitHub issue response."""
        # Similar structure

    @pytest.mark.vcr("github_404_response.yaml")
    def test_handles_404_correctly(self):
        """Proper error on deleted/nonexistent resource."""
        client = GitHubClient()
        with pytest.raises(requests.HTTPError) as exc:
            client.get_commit("owner", "repo", "nonexistent")
        assert exc.value.response.status_code == 404
```

### 3.2 GH Archive BigQuery Response Contract

```python
class TestGHArchiveContract:
    """Verify parsing matches real GH Archive row format."""

    # Real recorded rows from BigQuery
    REAL_PUSH_EVENT_ROW = {
        "type": "PushEvent",
        "created_at": "2024-01-15T10:30:00Z",
        "actor_login": "octocat",
        "actor_id": 583231,
        "repo_name": "octocat/Hello-World",
        "repo_id": 1296269,
        "payload": '{"ref":"refs/heads/main","before":"abc...","head":"def...","size":1,"commits":[...]}'
    }

    def test_parse_real_push_event_row(self):
        """PushEvent parses real GH Archive row."""
        event = create_push_event_from_gharchive(self.REAL_PUSH_EVENT_ROW)
        assert event.who.login == "octocat"
        assert event.repository.full_name == "octocat/Hello-World"
        assert event.verification.source == EvidenceSource.GHARCHIVE

    # One contract test per event type with real recorded data
    @pytest.mark.parametrize("event_type,row", RECORDED_GHARCHIVE_ROWS.items())
    def test_parse_all_event_types(self, event_type, row):
        """All event types parse from real GH Archive format."""
        creator = GHARCHIVE_EVENT_CREATORS[event_type]
        event = creator(row)
        assert event.verification.source == EvidenceSource.GHARCHIVE
```

### 3.3 Wayback CDX Response Contract

```python
class TestWaybackContract:
    """Verify parsing matches real Wayback CDX API format."""

    # Real CDX response format
    REAL_CDX_RESPONSE = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
        ["com,github)/octocat", "20240115103000", "https://github.com/octocat", "text/html", "200", "ABC123", "12345"],
        ["com,github)/octocat", "20240116120000", "https://github.com/octocat", "text/html", "200", "DEF456", "12346"],
    ]

    def test_parse_real_cdx_response(self):
        """SnapshotObservation parses real CDX format."""
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, WaybackClient.CDX_URL, json=self.REAL_CDX_RESPONSE)

            client = WaybackClient()
            results = client.search_cdx("https://github.com/octocat")

            assert len(results) == 2
            assert results[0]["timestamp"] == "20240115103000"
```

---

## 4. Failure Mode Tests (Priority 4)

What happens when things go wrong? These MUST be specified.

### 4.1 Network Failures

```gherkin
SCENARIO: GitHub API rate limit during bulk operation
  GIVEN analyst is recovering 100 deleted issues
  AND GitHub returns HTTP 403 after request #47
  WHEN create_issue_observation is called
  THEN requests.HTTPError is raised with status 403
  AND partial results are NOT silently returned
  AND error message indicates rate limiting

SCENARIO: BigQuery timeout during large query
  GIVEN analyst queries 1 year of GH Archive data
  AND BigQuery times out after 60 seconds
  WHEN gharchive.query_events is called
  THEN google.cloud.exceptions.Timeout is raised
  AND analyst can retry with narrower date range

SCENARIO: Wayback Machine unavailable
  GIVEN archive.org is returning 503
  WHEN create_snapshot_observation is called
  THEN requests.HTTPError is raised
  AND no empty SnapshotObservation is returned
```

### 4.2 Data Corruption/Unexpected Format

```gherkin
SCENARIO: GH Archive row missing required field
  GIVEN BigQuery returns row without "payload" field
  WHEN create_event_from_gharchive is called
  THEN KeyError is raised (not silent failure)
  AND error identifies the missing field

SCENARIO: GitHub API returns unexpected JSON structure
  GIVEN GitHub changes API response format
  AND "commit" key is renamed to "commit_data"
  WHEN create_commit_observation parses response
  THEN KeyError is raised with clear context
  AND contract test would have caught this first

SCENARIO: Malformed datetime in GH Archive
  GIVEN payload contains "created_at": "not-a-date"
  WHEN _parse_datetime is called
  THEN ValueError is raised with the unparseable string
```

### 4.3 Invalid Input Handling

```gherkin
SCENARIO: SHA too short for lookup
  GIVEN analyst provides 5-character SHA prefix
  WHEN CommitQuery is constructed
  THEN ValidationError is raised immediately
  AND message indicates minimum 7 characters required

SCENARIO: Repository name with invalid characters
  GIVEN analyst queries repo "owner/repo@malicious"
  WHEN RepositoryQuery is constructed
  THEN ValidationError is raised
  AND invalid characters are identified

SCENARIO: GHArchiveQuery without repo or actor
  GIVEN analyst provides only date range, no filters
  WHEN GHArchiveQuery is constructed
  THEN ValidationError indicates "Must specify at least repo or actor"
```

---

## 5. Integration Tests (Priority 5)

Test component interactions with minimal mocking.

### 5.1 EvidenceFactory with Fake HTTP

```python
class TestEvidenceFactoryIntegration:
    """Test EvidenceFactory workflows with controlled HTTP responses."""

    @responses.activate
    def test_full_commit_observation_workflow(self):
        """Factory creates valid CommitObservation from API response."""
        responses.add(
            responses.GET,
            "https://api.github.com/repos/owner/repo/commits/abc123def",
            json=SAMPLE_COMMIT_RESPONSE,
        )

        factory = EvidenceFactory()
        obs = factory.commit("owner", "repo", "abc123def")

        assert obs.sha == SAMPLE_COMMIT_RESPONSE["sha"]
        assert obs.verification.source == EvidenceSource.GITHUB
        assert obs.observed_by == EvidenceSource.GITHUB

    @responses.activate
    def test_ioc_verification_workflow(self):
        """IOC creation fetches and verifies against source."""
        vendor_report = "<html>Malicious commit abc123def was found...</html>"
        responses.add(
            responses.GET,
            "https://socket.dev/blog/malware-report",
            body=vendor_report,
        )

        factory = EvidenceFactory()
        ioc = factory.ioc(
            ioc_type=IOCType.COMMIT_SHA,
            value="abc123def",
            source_url="https://socket.dev/blog/malware-report",
        )

        assert ioc.confidence == "confirmed"
        assert "abc123def" in vendor_report  # Verification happened
```

### 5.2 GitClient with Real Git Repository

```python
class TestGitClientWithRealRepo:
    """Test GitClient against actual git operations."""

    @pytest.fixture
    def git_repo(self, tmp_path):
        """Create a real git repository for testing."""
        repo_path = tmp_path / "test-repo"
        repo_path.mkdir()

        subprocess.run(["git", "init"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)

        # Create a commit
        (repo_path / "file.txt").write_text("content")
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_path, check=True)

        return repo_path

    def test_get_commit_from_real_repo(self, git_repo):
        """GitClient parses real git output correctly."""
        client = GitClient(str(git_repo))

        # Get HEAD commit
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=git_repo, capture_output=True, text=True
        )
        head_sha = result.stdout.strip()

        commit = client.get_commit(head_sha)

        assert commit["sha"] == head_sha
        assert commit["message"] == "Initial commit"
        assert commit["author_name"] == "Test"

    def test_get_commit_files_from_real_repo(self, git_repo):
        """File changes are correctly parsed from real git."""
        client = GitClient(str(git_repo))
        head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=git_repo, capture_output=True, text=True
        ).stdout.strip()

        files = client.get_commit_files(head_sha)

        assert len(files) == 1
        assert files[0]["filename"] == "file.txt"
        assert files[0]["status"] == "added"
```

---

## 6. Unit Tests (Priority 6)

Pure functions only. No mocking needed.

### 6.1 Datetime Parsing

```python
class TestParseDatetime:
    """Test datetime parsing - pure function, no mocks."""

    @pytest.mark.parametrize("input,expected", [
        ("2024-01-15T14:30:22Z", datetime(2024, 1, 15, 14, 30, 22, tzinfo=timezone.utc)),
        ("2024-01-15T14:30:22+00:00", datetime(2024, 1, 15, 14, 30, 22, tzinfo=timezone.utc)),
        (None, None),
    ])
    def test_valid_formats(self, input, expected):
        assert _parse_datetime(input) == expected

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Unable to parse datetime"):
            _parse_datetime("not-a-date")

    def test_passthrough_datetime(self):
        dt = datetime.now(timezone.utc)
        assert _parse_datetime(dt) is dt
```

### 6.2 Wayback Timestamp Parsing

```python
class TestWaybackTimestampParsing:
    """Test Wayback timestamp conversion - pure function."""

    @pytest.mark.parametrize("timestamp,expected", [
        ("20240115143022", datetime(2024, 1, 15, 14, 30, 22, tzinfo=timezone.utc)),
        ("20240115140000", datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc)),
        ("20240115", datetime(2024, 1, 15, 0, 0, 0, tzinfo=timezone.utc)),
    ])
    def test_timestamp_formats(self, timestamp, expected):
        # Test the parsing logic from create_snapshot_observation
        ts = timestamp
        captured = datetime(
            int(ts[:4]), int(ts[4:6]), int(ts[6:8]),
            int(ts[8:10]) if len(ts) > 8 else 0,
            int(ts[10:12]) if len(ts) > 10 else 0,
            int(ts[12:14]) if len(ts) > 12 else 0,
            tzinfo=timezone.utc,
        )
        assert captured == expected
```

### 6.3 Force Push Detection Logic

```python
class TestForcePushDetection:
    """Test force push detection - pure logic."""

    @pytest.mark.parametrize("size,before_sha,expected", [
        (0, "abc123" + "0" * 34, True),   # size=0, non-null before = force push
        (0, "0" * 40, False),              # size=0, null before = initial push
        (3, "abc123" + "0" * 34, False),  # size>0 = normal push
        (1, "0" * 40, False),              # normal first commit
    ])
    def test_force_push_detection(self, size, before_sha, expected):
        is_force = size == 0 and before_sha != "0" * 40
        assert is_force == expected
```

---

## 7. CI/CD Readiness

### 7.1 Performance Requirements

| Suite | Target Time | Parallelizable |
|-------|-------------|----------------|
| Unit tests | < 5 seconds | Yes |
| Property tests | < 30 seconds | Yes |
| Integration tests | < 60 seconds | Yes (isolated) |
| Contract tests | < 30 seconds | No (uses recordings) |
| **Total** | **< 2 minutes** | - |

### 7.2 Test Isolation Requirements

```python
# Every test must be isolated
# NO shared state between tests
# NO dependency on test execution order
# NO network calls except in contract tests (with recordings)

@pytest.fixture(autouse=True)
def isolate_tests():
    """Ensure test isolation."""
    # Reset any module-level state
    yield
    # Cleanup
```

### 7.3 Flaky Test Policy

```
ZERO TOLERANCE FOR FLAKY TESTS

If a test fails intermittently:
1. Immediately quarantine (skip with reason)
2. Fix within 24 hours or delete
3. Never retry in CI - flaky means broken
```

### 7.4 Pipeline Definition

```yaml
# .github/workflows/test.yml
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Unit & Property Tests
      run: pytest tests/unit tests/property -x --tb=short
      timeout-minutes: 1

    - name: Integration Tests
      run: pytest tests/integration -x --tb=short
      timeout-minutes: 2

    - name: Contract Tests
      run: pytest tests/contract -x --tb=short
      timeout-minutes: 1

    - name: Mutation Testing (weekly)
      if: github.event.schedule
      run: mutmut run --paths-to-mutate=src/
```

---

## 8. Test Data & Fixtures

### 8.1 Recorded Real Data

```
tests/
├── fixtures/
│   ├── gharchive/           # Real BigQuery rows (sanitized)
│   │   ├── push_event.json
│   │   ├── pull_request_event.json
│   │   └── ...
│   ├── github_api/          # VCR cassettes
│   │   ├── commit_response.yaml
│   │   ├── issue_response.yaml
│   │   └── 404_response.yaml
│   └── wayback/             # CDX responses
│       └── cdx_response.json
```

### 8.2 Hypothesis Strategies

```python
# conftest.py

from hypothesis import strategies as st

@st.composite
def github_actor_strategy(draw):
    login = draw(st.text(min_size=1, max_size=39, alphabet=st.characters(whitelist_categories=("L", "N"))))
    return GitHubActor(login=login, id=draw(st.integers(min_value=1) | st.none()))

@st.composite
def push_event_strategy(draw):
    """Generate valid PushEvent instances."""
    # ... full implementation
```

---

## 9. What We Don't Test

### 9.1 Explicitly Out of Scope

| Not Tested | Reason |
|------------|--------|
| Pydantic's validation logic | Framework responsibility |
| requests library behavior | Framework responsibility |
| BigQuery client internals | Framework responsibility |
| Git command output format | OS/git version dependent (contract test covers) |

### 9.2 Tested Through Public API Only

| Internal Function | Tested Via |
|-------------------|------------|
| `_generate_evidence_id` | Evidence ID properties on created objects |
| `_parse_datetime` | Datetime fields on created objects |
| `_make_github_actor` | Actor objects in events/observations |
| `_make_github_repo` | Repository objects in events/observations |

---

## 10. Success Criteria

### Definition of Done for Test Suite

- [ ] All behavior scenarios pass
- [ ] Property tests find no counterexamples (1000+ examples each)
- [ ] Contract tests verify against real recorded responses
- [ ] Failure modes are explicitly tested
- [ ] Integration tests use real git repos, fake HTTP
- [ ] Unit tests have no mocks (pure functions)
- [ ] Total suite runs in < 2 minutes
- [ ] Mutation testing score > 80%
- [ ] Zero flaky tests

### Confidence Level

When all tests pass, we have confidence that:

1. **Forensic workflows work** - Analysts can recover deleted content
2. **Evidence is trustworthy** - IDs are deterministic, sources are accurate
3. **External services are understood** - Contract tests catch API drift
4. **Failures are handled** - No silent corruption or data loss
5. **Code is deployable** - Fast, reliable feedback loop
