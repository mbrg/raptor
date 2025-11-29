#!/usr/bin/env python3
"""
Unit tests for _clients.py module.

Tests the extracted client classes. These are mostly structural tests
since the actual API calls require network access (covered in integration tests).
"""

import pytest

from src._clients import GHArchiveClient, GitClient, GitHubClient, SourceClient, WaybackClient
from src._schema import EvidenceSource


# =============================================================================
# SOURCE CLIENT PROTOCOL TESTS
# =============================================================================


class TestSourceClientProtocol:
    """Test that all clients implement the SourceClient protocol."""

    def test_github_client_is_source_client(self):
        """GitHubClient implements SourceClient protocol."""
        client = GitHubClient()
        assert isinstance(client, SourceClient)

    def test_wayback_client_is_source_client(self):
        """WaybackClient implements SourceClient protocol."""
        client = WaybackClient()
        assert isinstance(client, SourceClient)

    def test_gharchive_client_is_source_client(self):
        """GHArchiveClient implements SourceClient protocol."""
        client = GHArchiveClient()
        assert isinstance(client, SourceClient)

    def test_git_client_is_source_client(self, tmp_path):
        """GitClient implements SourceClient protocol."""
        # Create a minimal git repo for testing
        import subprocess
        env = {"GIT_CONFIG_GLOBAL": "/dev/null", "HOME": str(tmp_path)}
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True, env=env)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True, check=True, env=env)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True, env=env)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp_path, capture_output=True, check=True, env=env)
        (tmp_path / "test.txt").write_text("test")
        subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True, env=env)
        subprocess.run(["git", "commit", "-m", "test"], cwd=tmp_path, capture_output=True, check=True, env=env)

        client = GitClient(str(tmp_path))
        assert isinstance(client, SourceClient)


# =============================================================================
# GITHUB CLIENT TESTS
# =============================================================================


class TestGitHubClient:
    """Test GitHubClient structure and properties."""

    def test_source_is_github(self):
        """Source property returns GITHUB."""
        client = GitHubClient()
        assert client.source == EvidenceSource.GITHUB

    def test_base_url(self):
        """BASE_URL is GitHub API."""
        assert GitHubClient.BASE_URL == "https://api.github.com"

    def test_lazy_session_creation(self):
        """Session is created lazily."""
        client = GitHubClient()
        assert client._session is None
        # We don't call _get_session() here to avoid network call

    def test_has_required_methods(self):
        """Client has all required methods."""
        client = GitHubClient()
        assert hasattr(client, "get_commit")
        assert hasattr(client, "get_issue")
        assert hasattr(client, "get_pull_request")
        assert hasattr(client, "get_file")
        assert hasattr(client, "get_branch")
        assert hasattr(client, "get_tag")
        assert hasattr(client, "get_release")
        assert hasattr(client, "get_forks")
        assert hasattr(client, "get_repo")


# =============================================================================
# WAYBACK CLIENT TESTS
# =============================================================================


class TestWaybackClient:
    """Test WaybackClient structure and properties."""

    def test_source_is_wayback(self):
        """Source property returns WAYBACK."""
        client = WaybackClient()
        assert client.source == EvidenceSource.WAYBACK

    def test_cdx_url(self):
        """CDX_URL is correct."""
        assert "web.archive.org/cdx" in WaybackClient.CDX_URL

    def test_has_required_methods(self):
        """Client has required methods."""
        client = WaybackClient()
        assert hasattr(client, "search_cdx")
        assert hasattr(client, "get_snapshot")
        assert hasattr(client, "check_availability")

    def test_archive_url(self):
        """ARCHIVE_URL is correct."""
        assert "web.archive.org/web" in WaybackClient.ARCHIVE_URL


# =============================================================================
# GHARCHIVE CLIENT TESTS
# =============================================================================


class TestGHArchiveClient:
    """Test GHArchiveClient structure and properties."""

    def test_source_is_gharchive(self):
        """Source property returns GHARCHIVE."""
        client = GHArchiveClient()
        assert client.source == EvidenceSource.GHARCHIVE

    def test_accepts_credentials_path(self):
        """Can initialize with credentials path."""
        client = GHArchiveClient(credentials_path="/path/to/creds.json")
        assert client.credentials_path == "/path/to/creds.json"

    def test_accepts_project_id(self):
        """Can initialize with project ID."""
        client = GHArchiveClient(project_id="my-project")
        assert client.project_id == "my-project"

    def test_lazy_client_creation(self):
        """BigQuery client is created lazily."""
        client = GHArchiveClient()
        assert client._client is None

    def test_has_query_events_method(self):
        """Client has query_events method."""
        client = GHArchiveClient()
        assert hasattr(client, "query_events")


# =============================================================================
# GIT CLIENT TESTS
# =============================================================================


@pytest.fixture
def git_repo(tmp_path):
    """Create a git repository for testing."""
    import subprocess

    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "HOME": str(tmp_path)}

    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp_path, capture_output=True, check=True, env=env)

    # Create initial commit
    (tmp_path / "test.txt").write_text("initial content")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=tmp_path, capture_output=True, check=True, env=env)

    # Create second commit
    (tmp_path / "test.txt").write_text("modified content")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True, env=env)
    subprocess.run(["git", "commit", "-m", "Second commit"], cwd=tmp_path, capture_output=True, check=True, env=env)

    return tmp_path


class TestGitClient:
    """Test GitClient structure and methods."""

    def test_source_is_git(self, git_repo):
        """Source property returns GIT."""
        client = GitClient(str(git_repo))
        assert client.source == EvidenceSource.GIT

    def test_accepts_repo_path(self, git_repo):
        """Can initialize with repo path."""
        client = GitClient(str(git_repo))
        assert client.repo_path == str(git_repo)

    def test_validates_git_repo(self, tmp_path):
        """Raises ValueError for non-git directory."""
        with pytest.raises(ValueError, match="Not a git repository"):
            GitClient(str(tmp_path))

    def test_has_required_methods(self, git_repo):
        """Client has required methods."""
        client = GitClient(str(git_repo))
        assert hasattr(client, "get_commit")
        assert hasattr(client, "get_commit_files")
        assert hasattr(client, "get_log")
        assert hasattr(client, "get_file_content")
        assert hasattr(client, "get_branches")
        assert hasattr(client, "get_tags")
        assert hasattr(client, "get_blame")
        assert hasattr(client, "get_remote_url")
        assert hasattr(client, "get_repo_info")

    def test_get_commit(self, git_repo):
        """Can get commit info."""
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=git_repo, capture_output=True, text=True, check=True
        )
        sha = result.stdout.strip()

        client = GitClient(str(git_repo))
        commit = client.get_commit(sha)

        assert commit["sha"] == sha
        assert commit["author"]["name"] == "Test User"
        assert commit["message"] == "Second commit"

    def test_get_log(self, git_repo):
        """Can get commit log."""
        client = GitClient(str(git_repo))
        log = client.get_log(limit=10)

        assert len(log) == 2
        assert log[0]["message"] == "Second commit"
        assert log[1]["message"] == "Initial commit"

    def test_get_commit_files(self, git_repo):
        """Can get files changed in commit."""
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=git_repo, capture_output=True, text=True, check=True
        )
        sha = result.stdout.strip()

        client = GitClient(str(git_repo))
        files = client.get_commit_files(sha)

        assert len(files) == 1
        assert files[0]["filename"] == "test.txt"
        assert files[0]["status"] == "modified"

    def test_get_file_content(self, git_repo):
        """Can get file content at ref."""
        client = GitClient(str(git_repo))
        content = client.get_file_content("test.txt", "HEAD")
        assert content == "modified content"

    def test_get_branches(self, git_repo):
        """Can list branches."""
        client = GitClient(str(git_repo))
        branches = client.get_branches()

        assert len(branches) >= 1
        # Should have master or main
        branch_names = [b["name"] for b in branches]
        assert "master" in branch_names or "main" in branch_names

    def test_get_repo_info(self, git_repo):
        """Can get repository info."""
        client = GitClient(str(git_repo))
        info = client.get_repo_info()

        assert "current_branch" in info
        assert "head_sha" in info


# =============================================================================
# CLIENT ISOLATION TESTS
# =============================================================================


class TestClientIsolation:
    """Test that clients are properly isolated."""

    def test_multiple_github_clients_independent(self):
        """Multiple GitHubClient instances are independent."""
        client1 = GitHubClient()
        client2 = GitHubClient()
        assert client1 is not client2
        assert client1._session is None
        assert client2._session is None

    def test_multiple_gharchive_clients_independent(self):
        """Multiple GHArchiveClient instances are independent."""
        client1 = GHArchiveClient(project_id="project1")
        client2 = GHArchiveClient(project_id="project2")
        assert client1 is not client2
        assert client1.project_id == "project1"
        assert client2.project_id == "project2"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
