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
    delete_gitea_user,
    delete_secret,
    ensure_gitea_user,
    ensure_secret,
    ensure_token,
    get_existing_secret_data,
    remove_all_collaborations,
    resolve_connection_params,
    sync_collaborators,
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


def _upsert_user(
    spec: kopf.Spec,
    body: kopf.Body,
    name: str,
    namespace: str,
    logger: kopf.Logger,
) -> dict[str, Any]:
    """Converge Gitea user state and K8s Secret to match spec."""
    gitea_url, admin_user, admin_pass = resolve_connection_params(spec)
    username: str = spec["username"]
    email: str = spec["email"]
    token_scopes: list[str] = list(spec.get("tokenScopes", ["repository"]))
    repositories: list[dict[str, str]] = list(spec.get("repositories", []))

    secret_name, secret_ns = _secret_location(spec, name, namespace)

    # Preserve existing credentials if the secret already exists.
    existing = get_existing_secret_data(secret_ns, secret_name)
    user_password = (existing or {}).get("password") or _generate_password()
    existing_token = (existing or {}).get("token")

    try:
        with _admin_client(gitea_url, admin_user, admin_pass) as client:
            ensure_gitea_user(client, username, email, user_password, logger)
            sync_collaborators(client, username, repositories, logger)
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
    **_: Any,
) -> dict[str, Any]:
    return _upsert_user(spec, body, name, namespace, logger)


@kopf.on.resume(CRD_GROUP, CRD_VERSION, "giteausers")
def resume_fn(
    spec: kopf.Spec,
    body: kopf.Body,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    return _upsert_user(spec, body, name, namespace, logger)


@kopf.on.update(
    CRD_GROUP, CRD_VERSION, "giteausers", field="spec", retries=3, backoff=15
)
def update_fn(
    spec: kopf.Spec,
    body: kopf.Body,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    return _upsert_user(spec, body, name, namespace, logger)


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
    secret_name, secret_ns = _secret_location(spec, name, namespace)

    try:
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
    **_: Any,
) -> dict[str, Any] | None:
    gitea_url, admin_user, admin_pass = resolve_connection_params(spec)
    username: str = spec["username"]
    repositories: list[dict[str, str]] = list(spec.get("repositories", []))
    secret_name, secret_ns = _secret_location(spec, name, namespace)

    drift_reason: str | None = None

    try:
        with _admin_client(gitea_url, admin_user, admin_pass) as client:
            if not user_exists(client, username):
                drift_reason = "user_missing"
            else:
                # Check each desired collaboration
                for entry in repositories:
                    repo_name = entry["name"]
                    desired_perm = entry["permission"]
                    owner, repo = repo_name.split("/", 1)
                    current_perm = _get_collaborator_permission(
                        client,
                        owner,
                        repo,
                        username,
                    )
                    if current_perm != desired_perm:
                        drift_reason = f"collaborator_mismatch:{repo_name}"
                        break
    except httpx.HTTPError as exc:
        raise kopf.TemporaryError(
            f"Drift check network error for {username!r}: {exc}",
            delay=60,
        ) from exc

    # Also check that the secret exists
    if drift_reason is None:
        existing = get_existing_secret_data(secret_ns, secret_name)
        if existing is None:
            drift_reason = "secret_missing"

    if drift_reason is not None:
        logger.warning(
            "Drift detected for GiteaUser %r: %s — remediating",
            username,
            drift_reason,
        )
        result = _upsert_user(spec, body, name, namespace, logger)
        return {**result, "drift": True, "driftReason": drift_reason}

    return None
