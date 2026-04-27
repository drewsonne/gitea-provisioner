# gitea-provisioner

A lightweight Kubernetes operator that provisions Gitea bot users, API tokens, SSH keys, repository access, and Actions secrets declaratively via CRDs.

Applications and automation pipelines can request their own Gitea credentials without manual Gitea admin access or pre-deploy scripts.

---

## What it does

The operator manages one CRD kind:

| Kind | What it provisions |
| --- | --- |
| `GiteaUser` | A Gitea user with an API token, SSH keys, repository collaborations, and Actions secrets |

All resources are reconciled continuously — the operator detects and repairs out-of-band drift every 5 minutes.

---

## Installation

Add the Helm repository:

```bash
helm repo add gitea-provisioner https://drewsonne.github.io/gitea-provisioner
helm repo update
```

Install the chart:

```bash
helm install gitea-provisioner gitea-provisioner/gitea-provisioner \
  --namespace gitea \
  --set gitea.url=http://gitea-http.gitea.svc.cluster.local \
  --set gitea.adminSecret.name=gitea-admin-credentials
```

---

## Requirements

* A running Gitea instance accessible from within the cluster
* A Kubernetes Secret containing Gitea admin credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gitea-admin-credentials
  namespace: gitea
stringData:
  username: admin
  password: <admin-password>
```

---

## Configuration

Default values:

```yaml
image:
  repository: drewsonne/gitea-provisioner
  tag: latest

gitea:
  url: http://gitea-http.gitea.svc.cluster.local
  adminSecret:
    name: gitea-admin-credentials

namespace: gitea
```

---

## Usage

### GiteaUser

Creates a Gitea user with a managed API token stored in a Kubernetes Secret.

```yaml
apiVersion: gitea.drewsonne.github.io/v1
kind: GiteaUser
metadata:
  name: gizmo
  namespace: gitea
spec:
  username: gizmo
  email: gizmo@example.com
```

#### Token scopes

Control what the generated API token can access. Defaults to `["repository"]`.

```yaml
spec:
  tokenScopes:
    - repository
    - issue
    - user
    - organization
```

Available scopes: `activitypub`, `admin`, `issue`, `misc`, `notification`, `organization`, `package`, `repository`, `user`.

#### Repository access

Grant the user collaborator access to specific repositories with a permission level.

```yaml
spec:
  repositories:
    - name: myorg/my-repo
      permission: write   # read | write | admin
    - name: myorg/other-repo
      permission: read
```

#### SSH keys

Register SSH public keys on the account. Keys are identified by their `name` (title in Gitea). The operator adds missing keys, replaces keys whose content has changed, and removes keys whose name is dropped from the list. Keys added outside this spec are never touched.

**Inline public key:**

```yaml
spec:
  sshKeys:
    - name: my-laptop
      publicKey: "ssh-ed25519 AAAA... user@host"
```

**From a Kubernetes Secret** (compatible with the [1Password operator](https://developer.1password.com/docs/k8s/k8s-operator/)):

```yaml
# The 1Password operator syncs the key into a Secret
apiVersion: onepassword.com/v1
kind: OnePasswordItem
metadata:
  name: drew-ssh-key
  namespace: gitea
spec:
  itemPath: "vaults/Home Lab/items/gitea-drew-ssh-key"
---
apiVersion: gitea.drewsonne.github.io/v1
kind: GiteaUser
metadata:
  name: drew
  namespace: gitea
spec:
  username: drew
  email: drew@example.com
  sshKeys:
    - name: home-lab
      secretRef:
        name: drew-ssh-key   # Secret created by OnePasswordItem above
        namespace: gitea
        key: "public key"    # field name within the 1Password item / Secret
```

#### Actions secrets

Set user-level Gitea Actions secrets sourced from Kubernetes Secrets. Secret values are always re-applied on reconcile (Gitea never returns values so drift can only be detected by name). Secrets removed from the list are deleted from Gitea.

```yaml
spec:
  actionsSecrets:
    - name: OP_SERVICE_ACCOUNT_TOKEN
      secretRef:
        name: op-service-account
        namespace: gitea
        key: token
    - name: REGISTRY_TOKEN
      secretRef:
        name: registry-credentials
        key: token           # namespace defaults to the CR's namespace
```

`secretRef` fields:

| Field | Required | Description |
| --- | --- | --- |
| `name` | yes | Name of the Kubernetes Secret |
| `key` | yes | Key within the Secret whose value is used |
| `namespace` | no | Namespace of the Secret; defaults to the CR's namespace |

#### Admin privileges

```yaml
spec:
  admin: true   # default: false
```

#### Custom token secret location

By default the token Secret is created as `{cr-name}-gitea-token` in the CR's namespace. Override with:

```yaml
spec:
  tokenSecretRef:
    name: my-bot-token
    namespace: other-namespace   # cross-namespace; no owner reference applied
```

#### Full example

```yaml
apiVersion: gitea.drewsonne.github.io/v1
kind: GiteaUser
metadata:
  name: gizmo
  namespace: gitea
spec:
  username: gizmo
  email: gizmo@sonne.zone
  admin: false
  tokenScopes:
    - repository
    - issue
    - user
    - organization
  repositories:
    - name: myorg/openclaw
      permission: write
    - name: myorg/docs
      permission: read
  sshKeys:
    - name: deploy-key
      secretRef:
        name: gizmo-ssh-key
        key: "public key"
  actionsSecrets:
    - name: OP_SERVICE_ACCOUNT_TOKEN
      secretRef:
        name: op-credentials
        key: token
  tokenSecretRef:
    name: openclaw-gitea-token
    namespace: gitea
```

---

## Per-CR credential override

Every CR accepts an optional `giteaAdminSecret` field to use credentials from a different Gitea instance (useful for multi-tenant setups):

```yaml
spec:
  giteaAdminSecret:
    name: my-other-gitea-admin
    namespace: gitea
```

The referenced Secret may contain `username`, `password`, and optionally `url` (overrides the `GITEA_URL` env var).

---

## Output

`GiteaUser` creates a Secret containing:

| Key | Description |
| --- | --- |
| `token` | The Gitea API token |
| `username` | The Gitea username |
| `password` | The user's Gitea password (for basic-auth clients) |
| `url` | The Gitea instance URL |

```bash
kubectl get secret gizmo-gitea-token -n gitea -o yaml
```

---

## Behaviour notes

* **Idempotent** — safe to reapply; existing Gitea resources are updated, not recreated
* **Credential preservation** — on resume or update, the existing password and token are reused from the Secret; the token is only regenerated if the Secret is missing or the token no longer exists in Gitea
* **SSH key tracking** — keys are tracked by their `name` (title); only keys whose title appears in the spec are ever modified or removed
* **Actions secrets** — values are always re-applied (Gitea does not return secret values); names dropped from the spec are deleted from Gitea
* **Drift detection** — a timer runs every 5 minutes per resource to detect and repair out-of-band changes (e.g. manual edits in the Gitea UI); drift is visible in `kubectl describe` as a K8s Warning event and in the `Drift` printer column
* **Repository removals** — collaborations added by the operator are only removed on CR deletion; repos removed from the spec mid-lifecycle are left in place until the CR is deleted

---

## Observability

```bash
kubectl get giteausers
```

Printer columns include `Username`, `Email`, `Admin`, `Ready`, `Drift`, and `Age`.

Drift events are also emitted as Kubernetes Warning events visible via `kubectl describe giteauser <name>`.

---

## Development

Build locally:

```bash
docker build -t drewsonne/gitea-provisioner:dev .
```

Run locally (requires cluster access):

```bash
docker run --rm \
  -e GITEA_URL=http://gitea-http.gitea.svc.cluster.local \
  -e GITEA_ADMIN_USERNAME=admin \
  -e GITEA_ADMIN_PASSWORD=... \
  drewsonne/gitea-provisioner:dev
```

---

## License

GPLv3
