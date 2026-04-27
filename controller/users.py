"""Kopf handlers for the GiteaUser CRD."""

from __future__ import annotations

import secrets
from typing import Any

import httpx
import kopf
from common import (
    CRD_GROUP,
    CRD_VERSION,
    MANAGED_TOKEN_NAME,
    _admin_client,
    _get_collaborator_permission,
    _list_user_ssh_keys,
    delete_gitea_user,
    delete_secret,
    ensure_gitea_user,
    ensure_secret,
    ensure_token,
    get_existing_secret_data,
    list_actions_secret_names,
    remove_all_actions_secrets,
    remove_all_collaborations,
    remove_all_ssh_keys,
    resolve_connection_params,
    sync_actions_secrets,
    sync_collaborators,
    sync_ssh_keys,
    user_exists,
)


def _generate_password() -> str:
    """Return a cryptographically random password suitable for Gitea."""
    return secrets.token_urlsafe(32)


def _secret_location(
    spec: kopf.Spec, cr_name: str, cr_namespace: str
) -> tuple[str, str]:
    """Return (secret_name, secret_namespace) for the token secret."""
    ref = spec.get("tokenSecretRef", {})
    return (
        ref.get("name", f"{cr_name}-gitea-token"),
        ref.get("namespace", cr_namespace),
    )


def _ssh_key_titles(spec: kopf.Spec) -> set[str]:
    return {e["name"] for e in spec.get("sshKeys", [])}


def _actions_secret_names(spec: kopf.Spec) -> set[str]:
    return {e["name"] for e in spec.get("actionsSecrets", [])}


def _upsert_user(
    spec: kopf.Spec,
    body: kopf.Body,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    patch: kopf.Patch,
    *,
    removed_ssh_titles: set[str] | None = None,
    removed_actions_names: set[str] | None = None,
) -> dict[str, Any]:
    """Converge Gitea user state to match spec."""
    gitea_url, admin_user, admin_pass = resolve_connection_params(spec)
    username: str = spec["username"]
    email: str = spec["email"]
    admin: bool = bool(spec.get("admin", False))
    token_scopes: list[str] = list(spec.get("tokenScopes", ["repository"]))
    repositories: list[dict[str, str]] = list(spec.get("repositories", []))
    ssh_keys: list[dict[str, Any]] = list(spec.get("sshKeys", []))
    actions_secrets: list[dict[str, Any]] = list(spec.get("actionsSecrets", []))

    secret_name, secret_ns = _secret_location(spec, name, namespace)

    # Preserve existing credentials if the secret already exists.
    existing = get_existing_secret_data(secret_ns, secret_name)
    user_password = (existing or {}).get("password") or _generate_password()
    existing_token = (existing or {}).get("token")

    try:
        with _admin_client(gitea_url, admin_user, admin_pass) as client:
            ensure_gitea_user(client, username, email, user_password, admin, logger)
            sync_collaborators(client, username, repositories, logger)
            if ssh_keys or removed_ssh_titles:
                sync_ssh_keys(
                    client,
                    gitea_url,
                    username,
                    user_password,
                    ssh_keys,
                    removed_ssh_titles or set(),
                    namespace,
                    logger,
                )
    except httpx.HTTPStatusError as exc:
        raise kopf.TemporaryError(
            f"Gitea API error for user {username!r}: "
            f"{exc.response.status_code} {exc.response.text}",
            delay=30,
        ) from exc
    except httpx.HTTPError as exc:
        raise kopf.TemporaryError(
            f"Gitea network error for user {username!r}: {exc}",
            delay=30,
        ) from exc

    try:
        token_value = ensure_token(
            gitea_url,
            username,
            user_password,
            MANAGED_TOKEN_NAME,
            token_scopes,
            existing_token,
            logger,
        )
    except httpx.HTTPStatusError as exc:
        raise kopf.TemporaryError(
            f"Token management error for {username!r}: "
            f"{exc.response.status_code} {exc.response.text}",
            delay=30,
        ) from exc
    except httpx.HTTPError as exc:
        raise kopf.TemporaryError(
            f"Token network error for {username!r}: {exc}",
            delay=30,
        ) from exc

    try:
        if actions_secrets or removed_actions_names:
            sync_actions_secrets(
                gitea_url,
                username,
                user_password,
                actions_secrets,
                removed_actions_names or set(),
                namespace,
                logger,
            )
    except httpx.HTTPStatusError as exc:
        raise kopf.TemporaryError(
            f"Actions secrets error for {username!r}: "
            f"{exc.response.status_code} {exc.response.text}",
            delay=30,
        ) from exc
    except httpx.HTTPError as exc:
        raise kopf.TemporaryError(
            f"Actions secrets network error for {username!r}: {exc}",
            delay=30,
        ) from exc

    ensure_secret(
        secret_ns,
        secret_name,
        body,
        {
            "token": token_value,
            "username": username,
            "password": user_password,
            "url": gitea_url,
        },
        logger,
    )

    # Write a consistent top-level ready flag regardless of which handler ran.
    patch.status["ready"] = True

    return {
        "ready": True,
        "username": username,
        "secretName": secret_name,
        "secretNamespace": secret_ns,
    }


# ---------------------------------------------------------------------------
# Kopf handlers
# ---------------------------------------------------------------------------


@kopf.on.create(
    CRD_GROUP, CRD_VERSION, "giteausers", retries=5, backoff=30, timeout=300
)
def create_fn(
    spec: kopf.Spec,
    body: kopf.Body,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    patch: kopf.Patch,
    **_: Any,
) -> dict[str, Any]:
    return _upsert_user(spec, body, name, namespace, logger, patch)


@kopf.on.resume(CRD_GROUP, CRD_VERSION, "giteausers")
def resume_fn(
    spec: kopf.Spec,
    body: kopf.Body,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    patch: kopf.Patch,
    **_: Any,
) -> dict[str, Any]:
    return _upsert_user(spec, body, name, namespace, logger, patch)


@kopf.on.update(
    CRD_GROUP, CRD_VERSION, "giteausers", field="spec", retries=3, backoff=15
)
def update_fn(
    spec: kopf.Spec,
    old: dict[str, Any],
    body: kopf.Body,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    patch: kopf.Patch,
    **_: Any,
) -> dict[str, Any]:
    old_spec = old.get("spec", {}) if old else {}

    # Compute what was explicitly removed so we can clean up in Gitea.
    old_ssh_titles = {e["name"] for e in old_spec.get("sshKeys", [])}
    new_ssh_titles = _ssh_key_titles(spec)
    removed_ssh = old_ssh_titles - new_ssh_titles

    old_actions_names = {e["name"] for e in old_spec.get("actionsSecrets", [])}
    new_actions_names = _actions_secret_names(spec)
    removed_actions = old_actions_names - new_actions_names

    return _upsert_user(
        spec,
        body,
        name,
        namespace,
        logger,
        patch,
        removed_ssh_titles=removed_ssh,
        removed_actions_names=removed_actions,
    )


@kopf.on.delete(
    CRD_GROUP, CRD_VERSION, "giteausers", retries=3, backoff=15, timeout=120
)
def delete_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    **_: Any,
) -> None:
    gitea_url, admin_user, admin_pass = resolve_connection_params(spec)
    username: str = spec["username"]
    repositories: list[dict[str, str]] = list(spec.get("repositories", []))
    ssh_key_titles = list(_ssh_key_titles(spec))
    actions_secret_names = list(_actions_secret_names(spec))
    secret_name, secret_ns = _secret_location(spec, name, namespace)

    # Read password from secret before deleting it — needed for user-auth ops.
    existing = get_existing_secret_data(secret_ns, secret_name)
    user_password = (existing or {}).get("password", "")

    try:
        if user_password:
            if ssh_key_titles:
                remove_all_ssh_keys(
                    gitea_url, username, user_password, ssh_key_titles, logger
                )
            if actions_secret_names:
                remove_all_actions_secrets(
                    gitea_url, username, user_password, actions_secret_names, logger
                )
        with _admin_client(gitea_url, admin_user, admin_pass) as client:
            remove_all_collaborations(client, username, repositories, logger)
            delete_gitea_user(client, username, logger)
    except httpx.HTTPStatusError as exc:
        raise kopf.TemporaryError(
            f"Gitea delete error for {username!r}: "
            f"{exc.response.status_code} {exc.response.text}",
            delay=30,
        ) from exc
    except httpx.HTTPError as exc:
        raise kopf.TemporaryError(
            f"Gitea network error during delete of {username!r}: {exc}",
            delay=30,
        ) from exc

    delete_secret(secret_name, secret_ns, logger)


def _check_gitea_drift(
    gitea_url: str,
    admin_user: str,
    admin_pass: str,
    username: str,
    repositories: list[dict[str, str]],
    desired_ssh_titles: set[str],
) -> str | None:
    """Check Gitea-side state via the admin API. Returns a drift reason or None."""
    with _admin_client(gitea_url, admin_user, admin_pass) as client:
        if not user_exists(client, username):
            return "user_missing"

        for entry in repositories:
            repo_name = entry["name"]
            owner, repo = repo_name.split("/", 1)
            current = _get_collaborator_permission(client, owner, repo, username)
            if current != entry["permission"]:
                return f"collaborator_mismatch:{repo_name}"

        if desired_ssh_titles:
            current_titles = {k["title"] for k in _list_user_ssh_keys(client, username)}
            missing = desired_ssh_titles - current_titles
            if missing:
                return f"ssh_keys_missing:{','.join(sorted(missing))}"

    return None


def _check_actions_drift(
    gitea_url: str,
    username: str,
    user_password: str,
    desired_actions_names: set[str],
) -> str | None:
    """Check Actions secret existence. Returns a drift reason or None."""
    current_names = list_actions_secret_names(gitea_url, username, user_password)
    missing = desired_actions_names - current_names
    if missing:
        return f"actions_secrets_missing:{','.join(sorted(missing))}"
    return None


@kopf.timer(
    CRD_GROUP,
    CRD_VERSION,
    "giteausers",
    interval=300,
    initial_delay=60,
    idle=30,
)
def check_drift(
    spec: kopf.Spec,
    body: kopf.Body,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    patch: kopf.Patch,
    **_: Any,
) -> dict[str, Any] | None:
    gitea_url, admin_user, admin_pass = resolve_connection_params(spec)
    username: str = spec["username"]
    repositories: list[dict[str, str]] = list(spec.get("repositories", []))
    desired_ssh_titles = _ssh_key_titles(spec)
    desired_actions_names = _actions_secret_names(spec)
    secret_name, secret_ns = _secret_location(spec, name, namespace)

    try:
        drift_reason = _check_gitea_drift(
            gitea_url,
            admin_user,
            admin_pass,
            username,
            repositories,
            desired_ssh_titles,
        )
    except httpx.HTTPError as exc:
        raise kopf.TemporaryError(
            f"Drift check network error for {username!r}: {exc}",
            delay=60,
        ) from exc

    # Actions secrets — values can't be compared; re-PUT on any name missing.
    if drift_reason is None and desired_actions_names:
        existing = get_existing_secret_data(secret_ns, secret_name)
        user_password = (existing or {}).get("password", "")
        if user_password:
            try:
                drift_reason = _check_actions_drift(
                    gitea_url, username, user_password, desired_actions_names
                )
            except httpx.HTTPError as exc:
                raise kopf.TemporaryError(
                    f"Actions secrets drift check failed for {username!r}: {exc}",
                    delay=60,
                ) from exc

    secret_absent = get_existing_secret_data(secret_ns, secret_name) is None
    if drift_reason is None and secret_absent:
        drift_reason = "secret_missing"

    if drift_reason is not None:
        logger.warning(
            "Drift detected for GiteaUser %r: %s — remediating",
            username,
            drift_reason,
        )
        result = _upsert_user(spec, body, name, namespace, logger, patch)
        return {**result, "drift": True, "driftReason": drift_reason}

    return None
