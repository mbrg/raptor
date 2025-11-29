"""
API Clients for GitHub Forensics Evidence Collection.

Clients for fetching data from various OSINT sources:
- GitHubClient: GitHub REST API (unauthenticated, 60 req/hr)
- WaybackClient: Wayback Machine CDX API
- GHArchiveClient: GH Archive BigQuery
- GitClient: Local git repository operations
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Protocol, runtime_checkable

from ._schema import EvidenceSource


@runtime_checkable
class SourceClient(Protocol):
    """Protocol for source clients."""

    @property
    def source(self) -> EvidenceSource: ...


class GitHubClient:
    """Client for GitHub REST API (unauthenticated OSINT).

    Rate limits: 60 requests/hour unauthenticated.
    All public repository data is accessible without authentication.
    """

    BASE_URL = "https://api.github.com"

    def __init__(self):
        self._session: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GITHUB

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
            self._session.headers.update({"Accept": "application/vnd.github+json"})
        return self._session

    def get_commit(self, owner: str, repo: str, sha: str) -> dict[str, Any]:
        """Fetch commit from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{sha}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_issue(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch issue from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{number}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_pull_request(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch PR from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{number}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_file(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> dict[str, Any]:
        """Fetch file content from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref}
        resp = session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_branch(self, owner: str, repo: str, branch: str) -> dict[str, Any]:
        """Fetch branch from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/branches/{branch}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_tag(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch tag from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/refs/tags/{tag}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_release(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch release by tag from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/releases/tags/{tag}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_forks(self, owner: str, repo: str, per_page: int = 100) -> list[dict[str, Any]]:
        """Fetch forks from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/forks"
        params = {"per_page": per_page}
        resp = session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        """Fetch repository info from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()


class WaybackClient:
    """Client for Wayback Machine CDX and Archive APIs.

    Provides access to:
    - CDX API: Search for archived snapshots of URLs
    - Archive API: Fetch archived page content
    """

    CDX_URL = "https://web.archive.org/cdx/search/cdx"
    ARCHIVE_URL = "https://web.archive.org/web"

    def __init__(self):
        self._session: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.WAYBACK

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
            # Wayback can be slow, use longer timeout
            self._session.timeout = 60
        return self._session

    def search_cdx(
        self,
        url: str,
        match_type: str = "exact",
        from_date: str | None = None,
        to_date: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, str]]:
        """Search CDX API for archived snapshots.

        Args:
            url: The URL to search for
            match_type: exact, prefix, host, or domain
            from_date: Start date (YYYYMMDD or YYYYMMDDHHmmss)
            to_date: End date (YYYYMMDD or YYYYMMDDHHmmss)
            limit: Max results to return

        Returns:
            List of snapshot records with keys: urlkey, timestamp, original,
            mimetype, statuscode, digest, length
        """
        session = self._get_session()
        params: dict[str, Any] = {
            "url": url,
            "output": "json",
            "matchType": match_type,
            "filter": "statuscode:200",
            "limit": limit,
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date

        resp = session.get(self.CDX_URL, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        if len(data) <= 1:
            return []

        headers = data[0]
        return [dict(zip(headers, row)) for row in data[1:]]

    def get_snapshot(self, url: str, timestamp: str) -> dict[str, Any]:
        """Fetch archived page content from Wayback Machine.

        Args:
            url: Original URL
            timestamp: Wayback timestamp (YYYYMMDDHHmmss format)

        Returns:
            Dict with 'content', 'url', 'timestamp', 'content_type'
        """
        session = self._get_session()
        archive_url = f"{self.ARCHIVE_URL}/{timestamp}id_/{url}"
        resp = session.get(archive_url, timeout=60)
        resp.raise_for_status()

        return {
            "content": resp.text,
            "url": url,
            "timestamp": timestamp,
            "content_type": resp.headers.get("content-type", ""),
            "archive_url": archive_url,
        }

    def check_availability(self, url: str) -> dict[str, Any] | None:
        """Check if a URL has been archived.

        Args:
            url: URL to check

        Returns:
            Dict with archive info if available, None otherwise
        """
        session = self._get_session()
        availability_url = "https://archive.org/wayback/available"
        resp = session.get(availability_url, params={"url": url}, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        snapshots = data.get("archived_snapshots", {})
        return snapshots.get("closest") if snapshots else None


class GHArchiveClient:
    """Client for GH Archive BigQuery queries."""

    def __init__(self, credentials_path: str | None = None, project_id: str | None = None):
        self.credentials_path = credentials_path
        self.project_id = project_id
        self._client: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GHARCHIVE

    def _get_client(self) -> Any:
        if self._client is None:
            from google.cloud import bigquery
            from google.oauth2 import service_account

            credentials = None
            project = self.project_id

            # First, try explicit credentials path
            if self.credentials_path:
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path, scopes=["https://www.googleapis.com/auth/bigquery"]
                )
                project = credentials.project_id
            else:
                # Check GOOGLE_APPLICATION_CREDENTIALS - could be path or JSON content
                creds_env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
                if creds_env:
                    # Strip surrounding quotes if present (shell quoting)
                    creds_env = creds_env.strip()
                    if creds_env.startswith("'") and creds_env.endswith("'"):
                        creds_env = creds_env[1:-1]
                    elif creds_env.startswith('"') and creds_env.endswith('"'):
                        creds_env = creds_env[1:-1]

                    # If it starts with '{', treat as JSON content
                    if creds_env.startswith("{"):
                        creds_info = json.loads(creds_env)
                        credentials = service_account.Credentials.from_service_account_info(
                            creds_info, scopes=["https://www.googleapis.com/auth/bigquery"]
                        )
                        project = creds_info.get("project_id", project)
                    elif os.path.exists(creds_env):
                        # It's a file path
                        credentials = service_account.Credentials.from_service_account_file(
                            creds_env, scopes=["https://www.googleapis.com/auth/bigquery"]
                        )
                        project = credentials.project_id

            if credentials:
                self._client = bigquery.Client(credentials=credentials, project=project)
            else:
                # Fall back to default credentials
                self._client = bigquery.Client(project=project)

        return self._client

    def query_events(
        self,
        repo: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
        from_date: str = "",
        to_date: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query GH Archive for events using parameterized queries."""
        from google.cloud import bigquery

        client = self._get_client()

        # Build table reference - use daily table
        # from_date is YYYYMMDDHHMM format (12 digits), extract day part
        day = from_date[:8]
        # Table names can't be parameterized, but day is validated format
        if not day.isdigit() or len(day) != 8:
            raise ValueError(f"Invalid date format: {from_date}")
        table = f"`githubarchive.day.{day}`"

        # Build WHERE clauses with parameterized values
        clauses = []
        params = []

        # Filter by hour and minute using created_at timestamp
        hour = int(from_date[8:10])
        minute = int(from_date[10:12])
        clauses.append("EXTRACT(HOUR FROM created_at) = @hour")
        clauses.append("EXTRACT(MINUTE FROM created_at) = @minute")
        params.append(bigquery.ScalarQueryParameter("hour", "INT64", hour))
        params.append(bigquery.ScalarQueryParameter("minute", "INT64", minute))

        if repo:
            clauses.append("repo.name = @repo")
            params.append(bigquery.ScalarQueryParameter("repo", "STRING", repo))
        if actor:
            clauses.append("actor.login = @actor")
            params.append(bigquery.ScalarQueryParameter("actor", "STRING", actor))
        if event_type:
            clauses.append("type = @event_type")
            params.append(bigquery.ScalarQueryParameter("event_type", "STRING", event_type))

        where = " AND ".join(clauses) if clauses else "1=1"

        query = f"""
        SELECT
            type,
            created_at,
            actor.login as actor_login,
            actor.id as actor_id,
            repo.name as repo_name,
            repo.id as repo_id,
            payload
        FROM {table}
        WHERE {where}
        ORDER BY created_at
        LIMIT 1000
        """

        job_config = bigquery.QueryJobConfig(query_parameters=params)
        results = client.query(query, job_config=job_config)
        return [dict(row) for row in results]


class GitClient:
    """Client for local git repository operations.

    Provides forensic evidence from local git repositories:
    - Commit history and details
    - File changes per commit
    - Branch and tag information
    - Blame attribution

    Useful for investigating cloned repositories or local development.
    """

    def __init__(self, repo_path: str = "."):
        """Initialize GitClient.

        Args:
            repo_path: Path to the git repository (default: current directory)
        """
        self.repo_path = repo_path
        self._validate_repo()

    def _validate_repo(self) -> None:
        """Validate that repo_path is a git repository."""
        try:
            self._run("rev-parse", "--git-dir")
        except subprocess.CalledProcessError:
            raise ValueError(f"Not a git repository: {self.repo_path}")

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GIT

    def _run(self, *args: str) -> str:
        """Run a git command and return output."""
        result = subprocess.run(
            ["git", "-C", self.repo_path, *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def get_commit(self, sha: str) -> dict[str, Any]:
        """Get detailed commit information.

        Args:
            sha: Commit SHA (full or abbreviated)

        Returns:
            Dict with sha, author, committer, message, parents, date
        """
        format_str = "%H%n%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%P%n%B"
        output = self._run("show", "-s", f"--format={format_str}", sha)
        lines = output.split("\n")

        return {
            "sha": lines[0],
            "author": {
                "name": lines[1],
                "email": lines[2],
                "date": lines[3],
            },
            "committer": {
                "name": lines[4],
                "email": lines[5],
                "date": lines[6],
            },
            "parents": lines[7].split() if lines[7] else [],
            "message": "\n".join(lines[8:]).strip(),
        }

    def get_commit_files(self, sha: str) -> list[dict[str, Any]]:
        """Get files changed in a commit.

        Args:
            sha: Commit SHA

        Returns:
            List of dicts with 'status' and 'filename'
        """
        output = self._run("diff-tree", "--no-commit-id", "--name-status", "-r", sha)
        files = []
        status_map = {"A": "added", "M": "modified", "D": "removed", "R": "renamed", "C": "copied"}

        for line in output.split("\n"):
            if line:
                parts = line.split("\t")
                status_code = parts[0][0]  # Handle R100, etc.
                files.append({
                    "status": status_map.get(status_code, "modified"),
                    "filename": parts[-1],
                })
        return files

    def get_log(
        self,
        ref: str = "HEAD",
        since: str | None = None,
        until: str | None = None,
        author: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get commit log with filtering.

        Args:
            ref: Branch, tag, or commit to start from
            since: Only commits after this date (ISO format or relative)
            until: Only commits before this date
            author: Filter by author name/email
            limit: Maximum commits to return

        Returns:
            List of commit dicts
        """
        args = ["log", f"--max-count={limit}", "--format=%H|%an|%ae|%aI|%s", ref]
        if since:
            args.append(f"--since={since}")
        if until:
            args.append(f"--until={until}")
        if author:
            args.append(f"--author={author}")

        output = self._run(*args)
        commits = []
        for line in output.split("\n"):
            if line:
                parts = line.split("|", 4)
                commits.append({
                    "sha": parts[0],
                    "author": {
                        "name": parts[1],
                        "email": parts[2],
                        "date": parts[3],
                    },
                    "message": parts[4] if len(parts) > 4 else "",
                })
        return commits

    def get_file_content(self, path: str, ref: str = "HEAD") -> str:
        """Get file content at a specific ref.

        Args:
            path: File path relative to repo root
            ref: Commit, branch, or tag

        Returns:
            File content as string
        """
        return self._run("show", f"{ref}:{path}")

    def get_branches(self, remote: bool = False) -> list[dict[str, Any]]:
        """Get list of branches.

        Args:
            remote: Include remote branches

        Returns:
            List of branch dicts with 'name', 'sha', 'is_current'
        """
        args = ["branch", "-v", "--format=%(refname:short)|%(objectname)|%(HEAD)"]
        if remote:
            args.append("-a")

        output = self._run(*args)
        branches = []
        for line in output.split("\n"):
            if line:
                parts = line.split("|")
                branches.append({
                    "name": parts[0],
                    "sha": parts[1],
                    "is_current": parts[2] == "*",
                })
        return branches

    def get_tags(self) -> list[dict[str, Any]]:
        """Get list of tags.

        Returns:
            List of tag dicts with 'name', 'sha', 'date'
        """
        output = self._run("tag", "-l", "--format=%(refname:short)|%(objectname)|%(creatordate:iso)")
        tags = []
        for line in output.split("\n"):
            if line:
                parts = line.split("|")
                tags.append({
                    "name": parts[0],
                    "sha": parts[1],
                    "date": parts[2] if len(parts) > 2 else None,
                })
        return tags

    def get_blame(self, path: str, ref: str = "HEAD") -> list[dict[str, Any]]:
        """Get blame information for a file.

        Args:
            path: File path relative to repo root
            ref: Commit, branch, or tag

        Returns:
            List of blame entries with 'sha', 'author', 'date', 'line_number', 'content'
        """
        output = self._run("blame", "--porcelain", ref, "--", path)
        entries = []
        current_sha = None
        current_data: dict[str, Any] = {}
        line_number = 0

        for line in output.split("\n"):
            if not line:
                continue

            # New blame entry starts with SHA
            if len(line) >= 40 and line[0:40].replace("^", "").isalnum():
                parts = line.split()
                current_sha = parts[0].lstrip("^")
                line_number = int(parts[2]) if len(parts) > 2 else line_number + 1
                current_data = {"sha": current_sha, "line_number": line_number}
            elif line.startswith("author "):
                current_data["author_name"] = line[7:]
            elif line.startswith("author-mail "):
                current_data["author_email"] = line[12:].strip("<>")
            elif line.startswith("author-time "):
                current_data["author_time"] = int(line[12:])
            elif line.startswith("\t"):
                current_data["content"] = line[1:]
                entries.append({
                    "sha": current_data.get("sha"),
                    "author": current_data.get("author_name"),
                    "email": current_data.get("author_email"),
                    "line_number": current_data.get("line_number"),
                    "content": current_data.get("content"),
                })

        return entries

    def get_remote_url(self, remote: str = "origin") -> str | None:
        """Get URL for a remote.

        Args:
            remote: Remote name

        Returns:
            Remote URL or None if not found
        """
        try:
            return self._run("remote", "get-url", remote)
        except subprocess.CalledProcessError:
            return None

    def get_repo_info(self) -> dict[str, Any]:
        """Get repository metadata.

        Returns:
            Dict with repo name, remotes, current branch, HEAD commit
        """
        remote_url = self.get_remote_url()
        current_branch = self._run("rev-parse", "--abbrev-ref", "HEAD")
        head_sha = self._run("rev-parse", "HEAD")

        # Extract owner/name from remote URL if possible
        owner, name = None, None
        if remote_url:
            # Handle both SSH and HTTPS URLs
            if "github.com" in remote_url:
                parts = remote_url.rstrip(".git").split("/")[-2:]
                if len(parts) == 2:
                    owner, name = parts

        return {
            "remote_url": remote_url,
            "current_branch": current_branch,
            "head_sha": head_sha,
            "owner": owner,
            "name": name,
        }
