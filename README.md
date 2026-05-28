# k8s-manifest-audit

> **k8s-manifest-audit** — static audit of Kubernetes manifests via MCP. Powered by kube-linter. Part of the Unbearable TechTips audit shop.

**Built by [Unbearable TechTips](https://github.com/UnbearableDev).** Pay-per-event pricing — only billed when a tool is actually called.

---

## What it does

Point any MCP-capable client (Claude Desktop, Cursor, n8n, Make, Zapier, custom agents) at this server, hand it a Kubernetes manifest or directory of manifests, get back a structured report:

- **Severity** — high / medium / low / info
- **Check ID** — kube-linter check name (e.g. `privileged-container`, `unset-cpu-requirements`)
- **Category** — security / resources / availability / network / rbac / images / config
- **Message** — what kube-linter found and where
- **Remediation hint** — what to do about it
- **Object location** — kind, name, namespace of the offending resource

63 checks total (31 enabled by default). Covers Deployment, Service, Ingress, ConfigMap, Secret, StatefulSet, DaemonSet, Job, CronJob, NetworkPolicy, RBAC, HPA, PDB, and more.

## Tools

| Tool | Pricing | Purpose |
|------|---------|---------|
| `audit_manifest(yaml_content)` | $0.02 | Audit a single YAML string (may contain multi-doc `---`) |
| `audit_directory(files)` | $0.02 | Audit multiple files — cross-file checks work correctly |
| `list_checks(enabled_only=False)` | $0.005 | Browse the full 63-check catalog with severity + category |
| `explain_check(check_id)` | $0.005 | Get description + remediation for one specific check |

## Quick start

```json
{
  "mcpServers": {
    "k8s-manifest-audit": {
      "url": "https://unbearable-dev--k8s-manifest-audit.apify.actor/mcp",
      "headers": { "Authorization": "Bearer <YOUR_APIFY_TOKEN>" }
    }
  }
}
```

## Check catalog (sample — 63 checks total)

| Check ID | Category | Severity (mapped) |
|----------|----------|-------------------|
| `privileged-container` | security | high |
| `privilege-escalation-container` | security | high |
| `run-as-non-root` | security | high |
| `env-var-secret` | security | high |
| `host-pid` / `host-ipc` / `host-network` | security | high |
| `wildcard-in-rules` | rbac | high |
| `cluster-admin-role-binding` | rbac | high |
| `unset-cpu-requirements` | resources | medium |
| `unset-memory-requirements` | resources | medium |
| `no-liveness-probe` / `no-readiness-probe` | availability | medium |
| `latest-tag` | images | medium |
| `minimum-three-replicas` | availability | medium |
| `no-rolling-update-strategy` | availability | medium |
| `dangling-service` / `dangling-ingress` | config | low |
| `use-namespace` | config | low |

Use `list_checks` to get the full, up-to-date catalog.

## Pricing

| Event | USD |
|-------|-----|
| `audit_manifest` or `audit_directory` call | $0.02 |
| `list_checks` or `explain_check` call | $0.005 |

Powered by [kube-linter](https://github.com/stackrox/kube-linter) (MIT, StackRox/Red Hat).

---

Built by Noel @ Unbearable TechTips — more like this in the [weekly newsletter](https://unbearabletechtips.beehiiv.com).
