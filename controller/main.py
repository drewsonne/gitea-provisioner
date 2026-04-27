"""gitea-provisioner operator entry point.

Importing the handler modules registers their kopf decorators.
"""

from __future__ import annotations

import logging
from typing import Any

import kopf
import users  # noqa: F401 — registers GiteaUser handlers


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    settings.peering.standalone = True
    settings.persistence.finalizer = "gitea.drewsonne.github.io/finalizer"

    # Store handler progress and diff-base in annotations under our own prefix
    # so we never collide with another operator or the kopf default namespace.
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix="gitea.drewsonne.github.io"
    )
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix="gitea.drewsonne.github.io",
        key="last-handled-configuration",
    )

    # After we patch a resource give the watch stream up to 10 s to deliver
    # the new resourceVersion before processing continues. Prevents
    # double-reconciliation on slow K3s clusters.
    settings.persistence.consistency_timeout = 10

    # Post WARNING+ logger messages from handlers as K8s events so that
    # "kubectl describe" surfaces drift detection and error details.
    settings.posting.level = logging.WARNING
    settings.posting.loggers = True

    # Explicit thread-pool size for sync handlers (httpx calls).
    settings.execution.max_workers = 20

    # Retry K8s API 5xx / network errors with an explicit backoff sequence.
    settings.networking.error_backoffs = [10, 20, 30, 60, 120]

    # Reconnect the watch stream if no events arrive for 90 s.
    settings.watching.inactivity_timeout = 90

    # Per-resource framework-error backoff sequence.
    settings.queueing.error_delays = [1, 2, 5, 10, 30, 60, 120]


@kopf.on.probe(id="alive")
def liveness_probe(**_: Any) -> bool:
    """Minimal liveness probe — confirms the operator event loop is running."""
    return True


@kopf.on.cleanup()
def on_shutdown(logger: kopf.Logger, **_: Any) -> None:
    logger.info("gitea-provisioner shutting down gracefully")
