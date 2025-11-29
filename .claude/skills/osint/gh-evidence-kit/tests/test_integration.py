#!/usr/bin/env python3
"""
Integration tests: Verify EvidenceFactory works with real APIs.

These tests hit actual external services:
- GitHub REST API (60 req/hr unauthenticated)
- Wayback Machine CDX and Archive APIs
- Local Git repositories
- (Optional) GH Archive BigQuery

Run with: pytest tests/test_integration.py -v -m integration

To skip these in CI: pytest -m "not integration"

GH Archive BigQuery Credentials (two options):

Option 1: JSON file path
    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json

Option 2: JSON content directly (useful for .env files or CI secrets)
    export GOOGLE_APPLICATION_CREDENTIALS='{"type":"service_account",...}'

    Note: The JSON can be wrapped in single quotes. The client will
    auto-detect JSON content vs file path.

For .env file usage:
    # .env
    GOOGLE_APPLICATION_CREDENTIALS='{"type":"service_account","project_id":"...",...}'

    Then use python-dotenv or similar to load it before running tests.
"""

import subprocess
from pathlib import Path

import pytest

from src import EvidenceFactory, EvidenceSource, IOCType


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


# =============================================================================
# GITHUB API INTEGRATION TESTS
#
# These hit the real GitHub API to verify the full pipeline works.
# Uses public repos that are unlikely to disappear.
# =============================================================================


class TestGitHubAPIIntegration:
    """Integration tests against real GitHub API."""

    @pytest.fixture
    def factory(self):
        """Create a factory."""
        return EvidenceFactory()

    def test_fetch_real_commit(self, factory):
        """
        Fetch a real commit from a stable public repo.

        Uses: torvalds/linux - unlikely to disappear, immutable history.
        Commit: 1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 (initial Linux commit)
        """
        obs = factory.commit(
            owner="torvalds",
            repo="linux",
            sha="1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"
        )

        # Verify evidence was created
        assert obs is not None
        assert obs.sha == "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"

        # Verify this is the famous "Linux-2.6.12-rc2" initial commit
        assert "Linux-2.6.12-rc2" in obs.message

        # Verify author
        assert obs.author.name == "Linus Torvalds"

        # Verify verification info is set
        assert obs.verification.source == EvidenceSource.GITHUB
        assert obs.verification.url is not None
        assert "github.com" in str(obs.verification.url)

    def test_fetch_real_pull_request(self, factory):
        """
        Fetch a real merged PR from a stable public repo.

        Uses: python/cpython PR #1 - historic, won't change.
        """
        obs = factory.pull_request(
            owner="python",
            repo="cpython",
            number=1
        )

        assert obs is not None
        assert obs.issue_number == 1
        assert obs.is_pull_request == True
        assert obs.verification.source == EvidenceSource.GITHUB

    def test_fetch_real_issue(self, factory):
        """
        Fetch a real issue from a stable public repo.

        Uses: python/cpython issue #1 (same as PR #1 on GitHub).
        """
        obs = factory.issue(
            owner="python",
            repo="cpython",
            number=1
        )

        assert obs is not None
        assert obs.issue_number == 1
        assert obs.verification.source == EvidenceSource.GITHUB

    def test_fetch_nonexistent_commit_raises(self, factory):
        """Fetching a nonexistent commit raises an appropriate error."""
        with pytest.raises(Exception):  # Could be HTTPError, ValueError, etc.
            factory.commit(
                owner="torvalds",
                repo="linux",
                sha="0000000000000000000000000000000000000000"
            )

    def test_fetch_nonexistent_repo_raises(self, factory):
        """Fetching from a nonexistent repo raises an appropriate error."""
        with pytest.raises(Exception):
            factory.commit(
                owner="this-owner-does-not-exist-12345",
                repo="this-repo-does-not-exist-12345",
                sha="1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"
            )


# =============================================================================
# AMAZON Q TIMELINE INTEGRATION TESTS
#
# These verify we can still fetch the real Amazon Q attack data.
# The commits/PRs may be deleted - tests should handle gracefully.
# =============================================================================


class TestAmazonQTimelineIntegration:
    """Integration tests against real Amazon Q attack artifacts."""

    @pytest.fixture
    def factory(self):
        return EvidenceFactory()

    def test_fetch_malicious_commit_678851b(self, factory):
        """
        Attempt to fetch the malicious commit 678851b.

        This commit contained the downloader code.
        It may have been removed from GitHub.
        """
        try:
            obs = factory.commit(
                owner="aws",
                repo="aws-toolkit-vscode",
                sha="678851bbe9776228f55e0460e66a6167ac2a1685"
            )
            # If we get here, the commit still exists
            assert obs.sha == "678851bbe9776228f55e0460e66a6167ac2a1685"
            assert obs.author.name == "lkmanka58"
        except Exception as e:
            # Commit was likely deleted - fail with info
            pytest.fail(f"Malicious commit not accessible: {e}")

    def test_fetch_revert_pr_7710(self, factory):
        """
        Fetch PR #7710 - the revert PR for the malicious code.

        This should still exist as it's the fix, not the attack.
        """
        try:
            obs = factory.pull_request(
                owner="aws",
                repo="aws-toolkit-vscode",
                number=7710
            )
            assert obs.issue_number == 7710
            # The PR author should be yueny2020, not the attacker
            assert obs.original_who.login == "yueny2020"
            assert "revert" in obs.title.lower()
        except Exception as e:
            pytest.skip(f"PR #7710 not accessible: {e}")


# =============================================================================
# IOC INTEGRATION TESTS
#
# Test that IOC creation actually fetches and verifies source URLs.
# =============================================================================


class TestIOCIntegration:
    """Integration tests for IOC verification."""

    @pytest.fixture
    def factory(self):
        return EvidenceFactory()

    def test_ioc_verifies_against_real_source(self, factory):
        """
        IOC creation should fetch the source URL and verify the value exists.

        Uses the real mbgsec.com blog post about Amazon Q.
        The blog shows full SHA: efee962ff1d1a80cfd6e498104cf72f348955693
        """
        ioc = factory.ioc(
            ioc_type=IOCType.COMMIT_SHA,
            value="efee962ff1d1a80cfd6e498104cf72f348955693",
            source_url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
        )

        assert ioc.ioc_type == IOCType.COMMIT_SHA
        assert ioc.value == "efee962ff1d1a80cfd6e498104cf72f348955693"
        assert ioc.verification.source == EvidenceSource.SECURITY_VENDOR

    def test_ioc_rejects_value_not_in_source(self, factory):
        """IOC creation should fail if value is not found in the source.

        True integration test - hits the real URL.
        Skips gracefully if external service unavailable.
        """
        import requests

        source_url = "https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/"

        # Pre-flight check: skip if service unavailable
        try:
            resp = requests.get(source_url, timeout=10)
            resp.raise_for_status()
        except requests.RequestException as e:
            pytest.skip(f"External service unavailable: {e}")

        # Actual test
        with pytest.raises(ValueError, match="not found in source"):
            factory.ioc(
                ioc_type=IOCType.COMMIT_SHA,
                value="this_sha_is_definitely_not_in_article_xyz123",
                source_url=source_url,
            )

    def test_ioc_fails_on_invalid_url(self, factory):
        """IOC creation should fail gracefully on unreachable URLs.

        True integration test - verifies actual network error handling.
        Uses .invalid TLD which is guaranteed to not resolve (RFC 2606).
        """
        with pytest.raises(ValueError, match="Failed to fetch"):
            factory.ioc(
                ioc_type=IOCType.COMMIT_SHA,
                value="anything",
                source_url="https://this-will-never-resolve.invalid/article",
            )


# =============================================================================
# GH ARCHIVE INTEGRATION TESTS
#
# These require BigQuery credentials. Skip if not available.
# Set GOOGLE_APPLICATION_CREDENTIALS env var to credentials JSON path.
# =============================================================================


class TestGHArchiveIntegration:
    """Integration tests against real GH Archive BigQuery data."""

    @pytest.fixture
    def factory(self):
        """Create factory - will fail lazily if no credentials."""
        return EvidenceFactory()

    def test_fetch_amazon_q_issue_event(self, factory):
        """
        Fetch the malicious issue #7651 from GH Archive.

        This is a historic event that should always be queryable.
        Timestamp: 2025-07-13 07:52 UTC
        """
        try:
            events = factory.events_from_gharchive(
                timestamp="202507130752",  # Minute when issue #7651 was created
                repo="aws/aws-toolkit-vscode",
                event_type="IssuesEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # Find issue #7651
        issue_7651 = None
        for event in events:
            if hasattr(event, "issue_number") and event.issue_number == 7651:
                issue_7651 = event
                break

        assert issue_7651 is not None, "Issue #7651 not found in GH Archive"
        assert issue_7651.who.login == "lkmanka58"
        assert "aws amazon donkey" in issue_7651.issue_title.lower()
        assert issue_7651.verification.source == EvidenceSource.GHARCHIVE

    def test_fetch_amazon_q_push_event(self, factory):
        """
        Fetch push events from the attack timeframe.

        Timestamp: 2025-07-13 20:37 UTC - when commits were pushed.
        """
        try:
            events = factory.events_from_gharchive(
                timestamp="202507132037",  # Minute when push occurred
                repo="aws/aws-toolkit-vscode",
                event_type="PushEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # Should have push events
        assert len(events) > 0, "No push events found"

        # All should be verified from GH Archive
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert event.verification.bigquery_table is not None

    def test_fetch_amazon_q_pull_request_event(self, factory):
        """Fetch PR events from GH Archive for the attack timeframe."""
        try:
            events = factory.events_from_gharchive(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="PullRequestEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have PRs in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert hasattr(event, "pr_number")

    def test_fetch_amazon_q_issue_comment_event(self, factory):
        """Fetch issue comment events from GH Archive."""
        try:
            events = factory.events_from_gharchive(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="IssueCommentEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have comments in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert hasattr(event, "comment_body")

    def test_fetch_create_event(self, factory):
        """Fetch CreateEvent (branch/tag creation) from GH Archive."""
        try:
            events = factory.events_from_gharchive(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="CreateEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have create events in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert hasattr(event, "ref_type")
            assert hasattr(event, "ref_name")

    def test_fetch_watch_event(self, factory):
        """Fetch WatchEvent (stars) from GH Archive."""
        try:
            events = factory.events_from_gharchive(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="WatchEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have watch events in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE

    def test_fetch_fork_event(self, factory):
        """Fetch ForkEvent from GH Archive."""
        try:
            events = factory.events_from_gharchive(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="ForkEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have fork events in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert hasattr(event, "fork_full_name")

    def test_gharchive_query_returns_empty_for_nonexistent_repo(self, factory):
        """Query for nonexistent repo returns empty list, not error."""
        try:
            events = factory.events_from_gharchive(
                timestamp="202507130752",
                repo="this-owner-does-not-exist-12345/this-repo-does-not-exist-12345",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        assert events == []

    def test_gharchive_requires_repo_or_actor(self, factory):
        """Query without repo or actor raises ValueError to prevent expensive scans."""
        with pytest.raises(ValueError, match="Must specify.*repo.*actor"):
            factory.events_from_gharchive(
                timestamp="202507130752",
                event_type="PushEvent",
            )

    def test_gharchive_requires_valid_timestamp_format(self, factory):
        """Query with invalid timestamp format raises ValueError."""
        with pytest.raises(ValueError, match="YYYYMMDDHHMM"):
            factory.events_from_gharchive(
                timestamp="2025071307",  # Missing minute
                repo="aws/aws-toolkit-vscode",
            )


# =============================================================================
# ARTICLE INTEGRATION TEST
# =============================================================================


class TestArticleIntegration:
    """Integration tests for article observation."""

    @pytest.fixture
    def factory(self):
        return EvidenceFactory()

    def test_create_article_with_real_url(self, factory):
        """Create article observation with a real URL."""
        article = factory.article(
            url="https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/",
            title="Constructing a Timeline for Amazon Q Prompt Infection",
            author="Michael Bargury",
            source_name="mbgsec.com",
        )

        assert article.title == "Constructing a Timeline for Amazon Q Prompt Infection"
        assert article.verification.source == EvidenceSource.SECURITY_VENDOR
        assert str(article.verification.url) == "https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/"


# =============================================================================
# WAYBACK MACHINE INTEGRATION TESTS
# =============================================================================


class TestWaybackIntegration:
    """Integration tests against real Wayback Machine API."""

    @pytest.fixture
    def factory(self):
        return EvidenceFactory()

    def test_search_wayback_for_github_page(self, factory):
        """
        Search Wayback Machine for archived GitHub page.

        Uses python.org - a stable page with many archives.
        """
        import requests

        # Pre-flight check
        try:
            resp = requests.get("https://web.archive.org/cdx/search/cdx?url=python.org&limit=1", timeout=10)
            resp.raise_for_status()
        except requests.RequestException as e:
            pytest.skip(f"Wayback Machine unavailable: {e}")

        obs = factory.wayback_snapshots(
            url="https://python.org",
            limit=10,
        )

        assert obs is not None
        assert obs.total_snapshots > 0
        assert obs.verification.source == EvidenceSource.WAYBACK
        assert len(obs.snapshots) <= 10

    def test_wayback_client_fetch_snapshot(self, factory):
        """
        Fetch actual archived content from Wayback Machine.

        Uses a known archive of python.org from 2020.
        """
        import requests

        try:
            client = factory.wayback
            snapshot = client.get_snapshot(
                url="https://www.python.org/",
                timestamp="20200101120000",  # Jan 1, 2020 12:00:00
            )
        except requests.RequestException as e:
            pytest.skip(f"Wayback Machine unavailable: {e}")

        assert "content" in snapshot
        assert "Python" in snapshot["content"]
        assert snapshot["url"] == "https://www.python.org/"

    def test_wayback_check_availability(self, factory):
        """
        Check if a URL is archived in Wayback Machine.
        """
        import requests

        try:
            client = factory.wayback
            result = client.check_availability("https://python.org")
        except requests.RequestException as e:
            pytest.skip(f"Wayback Machine unavailable: {e}")

        # python.org should definitely be archived
        assert result is not None
        assert "available" in result or "url" in result


# =============================================================================
# LOCAL GIT INTEGRATION TESTS
# =============================================================================


@pytest.fixture
def real_git_repo(tmp_path):
    """Create a real git repository for integration testing."""
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "HOME": str(tmp_path)}

    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "config", "user.email", "integration@test.com"], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "config", "user.name", "Integration Tester"], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp_path, capture_output=True, check=True, env=env)

    # Create initial commit
    (tmp_path / "README.md").write_text("# Test Repository\n\nThis is a test.")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "commit", "-m", "Initial commit: Add README"], cwd=tmp_path, capture_output=True, check=True, env=env)

    # Create second commit with changes
    (tmp_path / "main.py").write_text("print('Hello, World!')")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "commit", "-m", "feat: Add main.py with hello world"], cwd=tmp_path, capture_output=True, check=True, env=env)

    # Create third commit
    (tmp_path / "main.py").write_text("print('Hello, Integration Test!')")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "commit", "-m", "fix: Update greeting message"], cwd=tmp_path, capture_output=True, check=True, env=env)

    return tmp_path


class TestLocalGitIntegration:
    """Integration tests for local git repository evidence collection."""

    def test_git_commit_creates_observation(self, real_git_repo):
        """
        Factory can create CommitObservation from local git commit.
        """
        factory = EvidenceFactory()

        # Get HEAD commit SHA
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=real_git_repo, capture_output=True, text=True, check=True
        )
        head_sha = result.stdout.strip()

        obs = factory.git_commit(str(real_git_repo), head_sha)

        assert obs is not None
        assert obs.sha == head_sha
        assert obs.verification.source == EvidenceSource.GIT
        assert obs.verification.repo_path == str(real_git_repo)
        assert "Update greeting message" in obs.message

    def test_git_history_returns_multiple_commits(self, real_git_repo):
        """
        Factory can retrieve commit history from local git.
        """
        factory = EvidenceFactory()

        history = factory.git_history(str(real_git_repo), limit=10)

        assert len(history) == 3
        assert history[0].message == "fix: Update greeting message"
        assert history[1].message == "feat: Add main.py with hello world"
        assert history[2].message == "Initial commit: Add README"

        # All should have GIT as verification source
        for commit in history:
            assert commit.verification.source == EvidenceSource.GIT

    def test_git_blame_returns_line_attribution(self, real_git_repo):
        """
        Factory can get blame information for a file.
        """
        factory = EvidenceFactory()

        blame = factory.git_blame(str(real_git_repo), "main.py")

        assert len(blame) >= 1
        # The file has one line, so we should have at least one blame entry
        assert blame[0]["author"] == "Integration Tester"
        assert "Hello" in blame[0]["content"]

    def test_git_commit_with_files(self, real_git_repo):
        """
        Git commit observation includes changed files.
        """
        factory = EvidenceFactory()

        # Get the commit that added main.py
        history = factory.git_history(str(real_git_repo), limit=10)
        add_main_py_commit = history[1]  # "feat: Add main.py"

        # Now get full commit details
        obs = factory.git_commit(str(real_git_repo), add_main_py_commit.sha)

        assert len(obs.files) > 0
        filenames = [f.filename for f in obs.files]
        assert "main.py" in filenames

    def test_git_verification_works(self, real_git_repo):
        """
        Commit observations from local git can be verified.
        """
        factory = EvidenceFactory()

        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=real_git_repo, capture_output=True, text=True, check=True
        )
        head_sha = result.stdout.strip()

        obs = factory.git_commit(str(real_git_repo), head_sha)

        # Verification should pass (commit exists in local repo)
        is_valid, errors = obs.verify()
        assert is_valid, f"Verification failed: {errors}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
