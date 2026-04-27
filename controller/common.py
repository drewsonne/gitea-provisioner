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
    """Return an httpx Client authenticated as *username*.

    Gitea's token and SSH-key endpoints require basic auth as the target user,
    not an admin bearer token — even when the caller is a Gitea admin.
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
# Kubernetes Secret reference resolution
# ---------------------------------------------------------------------------


def resolve_secret_ref(ref: dict[str, str], cr_namespace: str) -> str:
    """Read a single value from a Kubernetes Secret reference.

    *ref* must contain ``name`` and ``key``; ``namespace`` is optional and
    defaults to *cr_namespace*.
    """
    ns = ref.get("namespace", cr_namespace)
    secret_name = ref["name"]
    key = ref["key"]
    data = get_existing_secret_data(ns, secret_name)
    if data is None:
        raise kopf.TemporaryError(
            f"Secret {ns}/{secret_name} referenced in secretRef not found.",
            delay=30,
        )
    if key not in data:
        raise kopf.PermanentError(
            f"Key {key!r} not found in secret {ns}/{secret_name}."
        )
    return data[key].strip()


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
    admin: bool,
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
                "admin": admin,
                "password": password,
            },
        )
        resp.raise_for_status()
        logger.info("Updated Gitea user %r (admin=%s)", username, admin)
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
        # CreateUserOption has no admin field — set it separately.
        if admin:
            client.patch(
                f"/admin/users/{username}",
                json={"login_name": username, "source_id": 0, "admin": True},
            ).raise_for_status()
            logger.info("Granted admin privileges to %r", username)


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
# Gitea token management (requires user's own credentials)
# ---------------------------------------------------------------------------


def list_user_tokens(user_client: httpx.Client, username: str) -> list[dict[str, Any]]:
    """List all tokens for *username*."""
    resp = user_client.get(f"/users/{username}/tokens")
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

    - Token exists in Gitea AND secret has the value → no-op; return stored value.
    - Token exists but secret is gone → delete and recreate to get a fresh value.
    - Token absent → create it.
    """
    with _user_client(url, username, password) as client:
        tokens = list_user_tokens(client, username)
        token_exists = any(t["name"] == token_name for t in tokens)

        if token_exists and existing_token_value:
            logger.debug(
                "Token %r already exists for %r and secret is intact — no-op",
                token_name,
                username,
            )
            return existing_token_value

        if token_exists:
            logger.warning(
                "Token %r exists in Gitea for %r but secret is missing — regenerating",
                token_name,
                username,
            )
            delete_user_token(client, username, token_name, logger)

        return create_user_token(client, username, token_name, scopes, logger)


# ---------------------------------------------------------------------------
# Gitea SSH key management (list via admin; add/delete via user credentials)
# ---------------------------------------------------------------------------


def resolve_ssh_public_key(entry: dict[str, Any], cr_namespace: str) -> str:
    """Return the SSH public key string from an sshKeys spec entry.

    Accepts either ``publicKey`` (inline string) or ``secretRef`` (reference to
    a Kubernetes Secret containing the public key).
    """
    if "publicKey" in entry:
        return str(entry["publicKey"]).strip()
    if "secretRef" in entry:
        return resolve_secret_ref(entry["secretRef"], cr_namespace)
    raise kopf.PermanentError(
        f"SSH key entry {entry.get('name')!r} must specify either "
        "'publicKey' or 'secretRef'."
    )


def _list_user_ssh_keys(
    admin_client: httpx.Client, username: str
) -> list[dict[str, Any]]:
    """List SSH public keys for *username* using admin credentials."""
    resp = admin_client.get(f"/users/{username}/keys")
    resp.raise_for_status()
    return resp.json()


def sync_ssh_keys(
    admin_client: httpx.Client,
    url: str,
    username: str,
    user_password: str,
    desired_entries: list[dict[str, Any]],
    removed_titles: set[str],
    cr_namespace: str,
    logger: kopf.Logger,
) -> None:
    """Reconcile SSH keys for *username* to match *desired_entries*.

    - Adds keys whose title is absent.
    - Replaces keys whose title matches but content differs (delete + re-add).
    - Deletes keys named in *removed_titles* (titles explicitly removed from spec).
    - Never touches keys with titles outside the desired+removed sets (leaves
      manually-added keys untouched).
    """
    current_keys = _list_user_ssh_keys(admin_client, username)
    current_by_title: dict[str, dict[str, Any]] = {k["title"]: k for k in current_keys}

    with _user_client(url, username, user_password) as uclient:
        # Ensure desired keys exist with correct content.
        for entry in desired_entries:
            title: str = entry["name"]
            public_key = resolve_ssh_public_key(entry, cr_namespace)
            existing = current_by_title.get(title)

            if existing is None:
                uclient.post(
                    "/user/keys",
                    json={"key": public_key, "read_only": False, "title": title},
                ).raise_for_status()
                logger.info("Added SSH key %r for user %r", title, username)
            elif existing["key"].strip() != public_key:
                # Content changed — replace.
                uclient.delete(f"/user/keys/{existing['id']}").raise_for_status()
                uclient.post(
                    "/user/keys",
                    json={"key": public_key, "read_only": False, "title": title},
                ).raise_for_status()
                logger.info(
                    "Replaced SSH key %r for user %r (content changed)", title, username
                )
            else:
                logger.debug("SSH key %r for %r already up-to-date", title, username)

        # Remove keys that were explicitly dropped from spec.
        for title in removed_titles:
            existing = current_by_title.get(title)
            if existing is not None:
                resp = uclient.delete(f"/user/keys/{existing['id']}")
                if resp.status_code != 404:
                    resp.raise_for_status()
                logger.info(
                    "Removed SSH key %r from %r (dropped from spec)", title, username
                )


def remove_all_ssh_keys(
    url: str,
    username: str,
    user_password: str,
    titles: list[str],
    logger: kopf.Logger,
) -> None:
    """Delete all SSH keys matching *titles* for *username*. Called on CR delete."""
    with _user_client(url, username, user_password) as uclient:
        # List via the user client since admin endpoint needs different path
        resp = uclient.get("/user/keys")
        resp.raise_for_status()
        current_keys: list[dict[str, Any]] = resp.json()
        titles_set = set(titles)
        for key in current_keys:
            if key["title"] in titles_set:
                dr = uclient.delete(f"/user/keys/{key['id']}")
                if dr.status_code != 404:
                    dr.raise_for_status()
                logger.info(
                    "Removed SSH key %r from %r (CR deleted)", key["title"], username
                )


# ---------------------------------------------------------------------------
# Gitea Actions secrets management (requires user credentials)
# ---------------------------------------------------------------------------


def list_actions_secret_names(url: str, username: str, user_password: str) -> set[str]:
    """Return the set of Actions secret names currently set for *username*.

    Secret values are never returned by Gitea — only the names are available.
    """
    with _user_client(url, username, user_password) as client:
        resp = client.get("/user/actions/secrets")
        if resp.status_code == 404:
            # Older Gitea versions may not support user-level Actions secrets.
            return set()
        resp.raise_for_status()
        return {s["name"] for s in resp.json()}


def sync_actions_secrets(
    url: str,
    username: str,
    user_password: str,
    desired_entries: list[dict[str, Any]],
    removed_names: set[str],
    cr_namespace: str,
    logger: kopf.Logger,
) -> None:
    """Reconcile Actions secrets for *username*.

    Sets all desired secrets (PUT is idempotent — creates or updates). Deletes
    secrets named in *removed_names* (explicitly dropped from spec).
    Gitea never returns secret values so we always re-PUT to stay converged.
    """
    with _user_client(url, username, user_password) as client:
        for entry in desired_entries:
            secret_name: str = entry["name"]
            value = resolve_secret_ref(entry["secretRef"], cr_namespace)
            resp = client.put(
                f"/user/actions/secrets/{secret_name}",
                json={"data": value},
            )
            if resp.status_code == 404:
                logger.warning(
                    "Actions secrets endpoint not available for %r — "
                    "Gitea version may be too old",
                    username,
                )
                return
            resp.raise_for_status()
            logger.info("Set Actions secret %r for user %r", secret_name, username)

        for secret_name in removed_names:
            resp = client.delete(f"/user/actions/secrets/{secret_name}")
            if resp.status_code not in {200, 204, 404}:
                resp.raise_for_status()
            logger.info(
                "Deleted Actions secret %r from %r (dropped from spec)",
                secret_name,
                username,
            )


def remove_all_actions_secrets(
    url: str,
    username: str,
    user_password: str,
    names: list[str],
    logger: kopf.Logger,
) -> None:
    """Delete all listed Actions secrets for *username*. Called on CR delete."""
    with _user_client(url, username, user_password) as client:
        for secret_name in names:
            resp = client.delete(f"/user/actions/secrets/{secret_name}")
            if resp.status_code not in {200, 204, 404}:
                resp.raise_for_status()
            logger.info(
                "Deleted Actions secret %r from %r (CR deleted)", secret_name, username
            )


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

    Adds missing collaborations and updates wrong permissions. Stale
    collaborations are only removed on CR deletion via remove_all_collaborations.
    """
    desired: dict[str, str] = {}
    for entry in repositories:
        repo_name = entry["name"]
        permission = entry["permission"]
        owner, repo = _parse_repo(repo_name)
        desired[f"{owner}/{repo}"] = permission

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
