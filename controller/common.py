"""Shared helpers for the gitea-provisioner operator."""

from __future__ import annotations

import base64
import os
from typing import Any

import httpx
import kopf
import kubernetes

GITEA_URL = os.environ["GITEA_URL"]
GITEA_ADMIN_USERNAME = os.environ["GITEA_ADMIN_USERNAME"]
GITEA_ADMIN_PASSWORD = os.environ["GITEA_ADMIN_PASSWORD"]

CRD_GROUP = "gitea.drewsonne.github.io"
CRD_VERSION = "v1"

# Fixed name for the operator-managed token on each Gitea user.
MANAGED_TOKEN_NAME = "kopf-provisioner"  # noqa: S105


# ---------------------------------------------------------------------------
# Gitea HTTP helpers
# ---------------------------------------------------------------------------


def _basic_auth_header(username: str, password: str) -> str:
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {credentials}"


def _admin_client(url: str, username: str, password: str) -> httpx.Client:
    """Return an httpx Client pre-configured with admin basic-auth."""
    return httpx.Client(
        base_url=f"{url.rstrip('/')}/api/v1",
        headers={
            "Authorization": _basic_auth_header(username, password),
            "Content-Type": "application/json",
        },
        timeout=15.0,
    )


def _user_client(url: str, username: str, password: str) -> httpx.Client:
    """Return an httpx Client pre-configured with a specific user's basic-auth.

    Gitea's token-management endpoints require basic auth as the target user,
    not a bearer token — even when the caller is an admin.
    """
    return httpx.Client(
        base_url=f"{url.rstrip('/')}/api/v1",
        headers={
            "Authorization": _basic_auth_header(username, password),
            "Content-Type": "application/json",
        },
        timeout=15.0,
    )


# ---------------------------------------------------------------------------
# Gitea user management (admin API)
# ---------------------------------------------------------------------------


def user_exists(client: httpx.Client, username: str) -> bool:
    """Return True if the Gitea user exists."""
    resp = client.get(f"/users/{username}")
    if resp.status_code == 404:
        return False
    resp.raise_for_status()
    return True


def ensure_gitea_user(
    client: httpx.Client,
    username: str,
    email: str,
    password: str,
    logger: kopf.Logger,
) -> None:
    """Create or update a Gitea user via the admin API."""
    if user_exists(client, username):
        resp = client.patch(
            f"/admin/users/{username}",
            json={
                "email": email,
                "login_name": username,
                "source_id": 0,
                "must_change_password": False,
            },
        )
        resp.raise_for_status()
        logger.info("Updated Gitea user %r", username)
    else:
        resp = client.post(
            "/admin/users",
            json={
                "username": username,
                "email": email,
                "password": password,
                "login_name": username,
                "source_id": 0,
                "must_change_password": False,
                "send_notify": False,
                "visibility": "private",
            },
        )
        resp.raise_for_status()
        logger.info("Created Gitea user %r", username)


def delete_gitea_user(
    client: httpx.Client,
    username: str,
    logger: kopf.Logger,
) -> None:
    """Delete a Gitea user. Silently ignores 404."""
    resp = client.delete(f"/admin/users/{username}", params={"purge": "true"})
    if resp.status_code == 404:
        logger.info("Gitea user %r already absent", username)
        return
    resp.raise_for_status()
    logger.info("Deleted Gitea user %r", username)


# ---------------------------------------------------------------------------
# Gitea token management (user API — requires user's own credentials)
# ---------------------------------------------------------------------------


def list_user_tokens(user_client: httpx.Client) -> list[dict[str, Any]]:
    """List all tokens for the authenticated user."""
    resp = user_client.get("/user/tokens")
    resp.raise_for_status()
    return resp.json()


def create_user_token(
    user_client: httpx.Client,
    username: str,
    token_name: str,
    scopes: list[str],
    logger: kopf.Logger,
) -> str:
    """Create a named API token for *username* and return the token value.

    The token value is only returned on creation; Gitea stores the hash only.
    """
    resp = user_client.post(
        f"/users/{username}/tokens",
        json={"name": token_name, "scopes": scopes},
    )
    resp.raise_for_status()
    token_value: str = resp.json()["sha1"]
    logger.info("Created token %r for user %r", token_name, username)
    return token_value


def delete_user_token(
    user_client: httpx.Client,
    username: str,
    token_name: str,
    logger: kopf.Logger,
) -> None:
    """Delete a named token for *username*. Silently ignores 404."""
    resp = user_client.delete(f"/users/{username}/tokens/{token_name}")
    if resp.status_code == 404:
        logger.debug("Token %r for user %r already absent", token_name, username)
        return
    resp.raise_for_status()
    logger.info("Deleted token %r for user %r", token_name, username)


def ensure_token(
    url: str,
    username: str,
    password: str,
    token_name: str,
    scopes: list[str],
    existing_token_value: str | None,
    logger: kopf.Logger,
) -> str:
    """Ensure the managed token exists and return its value.

    - If the token exists in Gitea AND we have the value in the secret:
      no-op; return the stored value.
    - If the token exists in Gitea but we lost the value (secret gone):
      delete and recreate to obtain a fresh value.
    - If the token does not exist: create it.
    """
    with _user_client(url, username, password) as client:
        tokens = list_user_tokens(client)
        token_exists = any(t["name"] == token_name for t in tokens)

        if token_exists and existing_token_value:
            logger.debug(
                "Token %r already exists for %r and secret is intact — no-op",
                token_name,
                username,
            )
            return existing_token_value

        if token_exists:
            # Value was lost (secret deleted externally) — regenerate.
            logger.warning(
                "Token %r exists in Gitea for %r but secret is missing — regenerating",
                token_name,
                username,
            )
            delete_user_token(client, username, token_name, logger)

        return create_user_token(client, username, token_name, scopes, logger)


# ---------------------------------------------------------------------------
# Gitea repository collaborator management
# ---------------------------------------------------------------------------


def _parse_repo(repo_name: str) -> tuple[str, str]:
    """Split 'owner/repo' into (owner, repo). Raises PermanentError on bad format."""
    parts = repo_name.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise kopf.PermanentError(
            f"Invalid repository name {repo_name!r}; expected 'owner/repo' format."
        )
    return parts[0], parts[1]


def _get_collaborator_permission(
    client: httpx.Client,
    owner: str,
    repo: str,
    username: str,
) -> str | None:
    """Return the current permission for *username* on owner/repo, or None."""
    resp = client.get(f"/repos/{owner}/{repo}/collaborators/{username}/permission")
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json().get("permission")


def sync_collaborators(
    client: httpx.Client,
    username: str,
    repositories: list[dict[str, str]],
    logger: kopf.Logger,
) -> None:
    """Reconcile repository collaborations to match *repositories* spec.

    Adds missing collaborations, updates wrong permissions, and removes any
    collaborations not listed in the spec.
    """
    desired: dict[str, str] = {}
    for entry in repositories:
        repo_name = entry["name"]
        permission = entry["permission"]
        owner, repo = _parse_repo(repo_name)
        desired[f"{owner}/{repo}"] = permission

    # Add / update desired collaborations
    for repo_name, permission in desired.items():
        owner, repo = _parse_repo(repo_name)
        current = _get_collaborator_permission(client, owner, repo, username)
        if current == permission:
            logger.debug(
                "Collaborator %r on %r already has permission %r",
                username,
                repo_name,
                permission,
            )
            continue
        resp = client.put(
            f"/repos/{owner}/{repo}/collaborators/{username}",
            json={"permission": permission},
        )
        if resp.status_code == 404:
            raise kopf.TemporaryError(
                f"Repository {repo_name!r} not found in Gitea. "
                "Ensure it exists before referencing it.",
                delay=60,
            )
        resp.raise_for_status()
        action = "Updated" if current else "Added"
        logger.info(
            "%s collaborator %r on %r with permission %r",
            action,
            username,
            repo_name,
            permission,
        )

    # Removals of stale collaborations happen only in remove_all_collaborations
    # (called on CR delete). Iterating all repos a user has access to is
    # expensive and not needed for the normal convergence loop.

    # To find stale collaborations we'd need to iterate all repos the user
    # has access to, which is expensive. Instead we remove collaborations only
    # from repos that were previously managed (tracked via spec diff by kopf).
    # For an explicit cleanup, callers should pass an empty repositories list
    # before deleting the CR, or rely on GiteaUser delete handler.


def remove_all_collaborations(
    client: httpx.Client,
    username: str,
    repositories: list[dict[str, str]],
    logger: kopf.Logger,
) -> None:
    """Remove *username* as a collaborator from all listed repositories."""
    for entry in repositories:
        repo_name = entry["name"]
        owner, repo = _parse_repo(repo_name)
        resp = client.delete(f"/repos/{owner}/{repo}/collaborators/{username}")
        if resp.status_code == 404:
            logger.debug("Collaborator %r on %r already absent", username, repo_name)
            continue
        resp.raise_for_status()
        logger.info("Removed collaborator %r from %r", username, repo_name)


# ---------------------------------------------------------------------------
# Connection parameter resolution
# ---------------------------------------------------------------------------


def resolve_connection_params(spec: kopf.Spec) -> tuple[str, str, str]:
    """Return (url, admin_username, admin_password) for the Gitea admin API.

    If the CR specifies ``giteaAdminSecret``, read credentials from that
    secret.  Otherwise fall back to the global env vars.
    """
    override_secret = spec.get("giteaAdminSecret")
    if override_secret:
        v1 = kubernetes.client.CoreV1Api()
        try:
            secret = v1.read_namespaced_secret(
                name=override_secret["name"],
                namespace=override_secret["namespace"],
            )
        except kubernetes.client.exceptions.ApiException as exc:
            raise kopf.TemporaryError(
                f"Cannot read Gitea admin secret "
                f"{override_secret['namespace']}/{override_secret['name']}: {exc}",
                delay=30,
            ) from exc
        data = secret.data or {}
        username = (
            base64.b64decode(data["username"]).decode()
            if "username" in data
            else GITEA_ADMIN_USERNAME
        )
        password = base64.b64decode(data["password"]).decode()
        url = base64.b64decode(data["url"]).decode() if "url" in data else GITEA_URL
        return url, username, password
    return GITEA_URL, GITEA_ADMIN_USERNAME, GITEA_ADMIN_PASSWORD


# ---------------------------------------------------------------------------
# Kubernetes Secret helpers
# ---------------------------------------------------------------------------


def get_existing_secret_data(
    namespace: str,
    secret_name: str,
) -> dict[str, str] | None:
    """Read and base64-decode all keys from an existing Secret, or return None."""
    v1 = kubernetes.client.CoreV1Api()
    try:
        secret = v1.read_namespaced_secret(name=secret_name, namespace=namespace)
        return {k: base64.b64decode(v).decode() for k, v in (secret.data or {}).items()}
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status == 404:
            return None
        raise kopf.TemporaryError(
            f"Failed reading secret {namespace}/{secret_name}: {exc}",
            delay=15,
        ) from exc


def ensure_secret(
    namespace: str,
    secret_name: str,
    body: kopf.Body,
    data: dict[str, str],
    logger: kopf.Logger,
) -> None:
    """Create or update a Kubernetes Secret with the supplied string data.

    Skips the patch when the secret already contains identical values to
    avoid churning resourceVersion unnecessarily.
    """
    v1 = kubernetes.client.CoreV1Api()
    secret_body = kubernetes.client.V1Secret(
        metadata=kubernetes.client.V1ObjectMeta(name=secret_name),
        string_data=data,
    )
    # Owner references cannot cross namespaces.
    if namespace == body["metadata"]["namespace"]:
        kopf.adopt(secret_body)

    try:
        v1.create_namespaced_secret(namespace=namespace, body=secret_body)
        logger.info("Created secret %s/%s", namespace, secret_name)
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status == 409:
            existing = v1.read_namespaced_secret(name=secret_name, namespace=namespace)
            existing_data = {
                k: base64.b64decode(v).decode()
                for k, v in (existing.data or {}).items()
            }
            if existing_data == data:
                logger.debug(
                    "Secret %s already up-to-date, skipping patch",
                    secret_name,
                )
                return
            v1.patch_namespaced_secret(
                name=secret_name,
                namespace=namespace,
                body={"stringData": data},
            )
            logger.info("Updated secret %s/%s", namespace, secret_name)
        else:
            raise kopf.TemporaryError(
                f"Kubernetes API error on secret {secret_name}: {exc}",
                delay=15,
            ) from exc


def delete_secret(
    secret_name: str,
    secret_ns: str,
    logger: kopf.Logger,
) -> None:
    """Delete a Kubernetes Secret, ignoring 404."""
    v1 = kubernetes.client.CoreV1Api()
    try:
        v1.delete_namespaced_secret(name=secret_name, namespace=secret_ns)
        logger.info("Deleted secret %s/%s", secret_ns, secret_name)
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status != 404:
            raise kopf.TemporaryError(
                f"Failed to delete secret {secret_name}: {exc}",
                delay=15,
            ) from exc
        logger.debug("Secret %s/%s already absent", secret_ns, secret_name)
