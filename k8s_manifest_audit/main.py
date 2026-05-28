"""k8s-manifest-audit — MCP server powered by kube-linter."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
import time
from collections.abc import Mapping, MutableMapping
from typing import Any, Literal

import uvicorn
from apify import Actor
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.types import Receive, Scope, Send

Severity = Literal["high", "medium", "low", "info"]

KUBE_LINTER_BIN = os.environ.get("KUBE_LINTER_BIN", "kube-linter")

# kube-linter severity is expressed as check names + context; we map by check name patterns.
# The binary doesn't emit a severity field in JSON — we derive it from check metadata.
# Checks that fire on privileged/root/escape = high, resource/probe = medium, config = low/info.
SEVERITY_MAP: dict[str, Severity] = {
    # high — privilege / escape / secret exposure
    "privileged-container": "high",
    "privilege-escalation-container": "high",
    "run-as-non-root": "high",
    "no-read-only-root-fs": "medium",
    "env-var-secret": "high",
    "read-secret-from-env-var": "high",
    "docker-sock": "high",
    "host-pid": "high",
    "host-ipc": "high",
    "host-network": "high",
    "sensitive-host-mounts": "high",
    "writable-host-mount": "high",
    "unsafe-proc-mount": "high",
    "unsafe-sysctls": "high",
    "scc-deny-privileged-container": "high",
    "drop-net-raw-capability": "medium",
    "privileged-ports": "medium",
    "ssh-port": "medium",
    "wildcard-in-rules": "high",
    "cluster-admin-role-binding": "high",
    "access-to-secrets": "high",
    "access-to-create-pods": "high",
    # medium — availability / resources / probes
    "unset-cpu-requirements": "medium",
    "unset-memory-requirements": "medium",
    "no-liveness-probe": "medium",
    "no-readiness-probe": "medium",
    "latest-tag": "medium",
    "minimum-three-replicas": "medium",
    "hpa-minimum-three-replicas": "medium",
    "no-rolling-update-strategy": "medium",
    "no-anti-affinity": "medium",
    "pdb-min-available": "medium",
    "pdb-max-unavailable": "medium",
    "pdb-unhealthy-pod-eviction-policy": "medium",
    "non-isolated-pod": "medium",
    "exposed-services": "medium",
    "restart-policy": "medium",
    # low — config / best-practice
    "dangling-service": "low",
    "dangling-ingress": "low",
    "dangling-networkpolicy": "low",
    "dangling-networkpolicypeer-podselector": "low",
    "dangling-horizontalpodautoscaler": "low",
    "dangling-servicemonitor": "low",
    "mismatching-selector": "low",
    "non-existent-service-account": "low",
    "default-service-account": "low",
    "deprecated-service-account-field": "low",
    "no-extensions-v1beta": "low",
    "use-namespace": "low",
    "schema-validation": "low",
    "duplicate-env-var": "low",
    "env-value-from": "low",
    "invalid-target-ports": "low",
    "liveness-port": "low",
    "readiness-port": "low",
    "startup-port": "low",
    "job-ttl-seconds-after-finished": "low",
    "dnsconfig-options": "low",
    "no-node-affinity": "low",
    "priority-class-name": "info",
    "required-annotation-email": "info",
    "required-label-owner": "info",
    "sorted-keys": "info",
}

CATEGORY_MAP: dict[str, str] = {
    "privileged-container": "security",
    "privilege-escalation-container": "security",
    "run-as-non-root": "security",
    "no-read-only-root-fs": "security",
    "env-var-secret": "security",
    "read-secret-from-env-var": "security",
    "docker-sock": "security",
    "host-pid": "security",
    "host-ipc": "security",
    "host-network": "security",
    "sensitive-host-mounts": "security",
    "writable-host-mount": "security",
    "unsafe-proc-mount": "security",
    "unsafe-sysctls": "security",
    "scc-deny-privileged-container": "security",
    "drop-net-raw-capability": "security",
    "privileged-ports": "security",
    "ssh-port": "security",
    "wildcard-in-rules": "rbac",
    "cluster-admin-role-binding": "rbac",
    "access-to-secrets": "rbac",
    "access-to-create-pods": "rbac",
    "unset-cpu-requirements": "resources",
    "unset-memory-requirements": "resources",
    "no-liveness-probe": "availability",
    "no-readiness-probe": "availability",
    "latest-tag": "images",
    "minimum-three-replicas": "availability",
    "hpa-minimum-three-replicas": "availability",
    "no-rolling-update-strategy": "availability",
    "no-anti-affinity": "availability",
    "pdb-min-available": "availability",
    "pdb-max-unavailable": "availability",
    "pdb-unhealthy-pod-eviction-policy": "availability",
    "non-isolated-pod": "network",
    "exposed-services": "network",
    "dangling-service": "config",
    "dangling-ingress": "config",
    "dangling-networkpolicy": "network",
    "dangling-networkpolicypeer-podselector": "network",
    "dangling-horizontalpodautoscaler": "config",
    "dangling-servicemonitor": "config",
    "mismatching-selector": "config",
    "non-existent-service-account": "config",
    "default-service-account": "config",
    "deprecated-service-account-field": "config",
    "no-extensions-v1beta": "config",
    "use-namespace": "config",
    "schema-validation": "config",
    "duplicate-env-var": "config",
    "env-value-from": "config",
    "invalid-target-ports": "config",
    "liveness-port": "availability",
    "readiness-port": "availability",
    "startup-port": "availability",
    "job-ttl-seconds-after-finished": "config",
    "dnsconfig-options": "config",
    "no-node-affinity": "config",
    "restart-policy": "availability",
    "priority-class-name": "config",
    "required-annotation-email": "config",
    "required-label-owner": "config",
    "sorted-keys": "config",
}

_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}


def _map_severity(check_name: str) -> Severity:
    return SEVERITY_MAP.get(check_name, "low")


def _map_category(check_name: str) -> str:
    return CATEGORY_MAP.get(check_name, "config")


def _run_kube_linter(yaml_path: str) -> tuple[dict[str, Any], int]:
    """Run kube-linter lint --format json on a path. Returns (parsed_json, exit_code)."""
    result = subprocess.run(
        [KUBE_LINTER_BIN, "lint", "--format", "json", yaml_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        data = {"Reports": [], "Checks": [], "_raw_stderr": result.stderr}
    return data, result.returncode


def _reports_to_findings(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for r in reports:
        check_name = r.get("Check", "unknown")
        obj = r.get("Object", {})
        k8s = obj.get("K8sObject", {})
        meta = obj.get("Metadata", {})
        findings.append({
            "id": check_name,
            "severity": _map_severity(check_name),
            "category": _map_category(check_name),
            "message": r.get("Diagnostic", {}).get("Message", ""),
            "remediation_hint": r.get("Remediation", ""),
            "line": None,  # kube-linter doesn't emit line numbers in JSON output
            "object_kind": k8s.get("GroupVersionKind", {}).get("Kind", ""),
            "object_name": k8s.get("Name", ""),
            "object_namespace": k8s.get("Namespace", ""),
            "file_path": meta.get("FilePath", ""),
        })
    return findings


def _get_checks_catalog() -> list[dict[str, Any]]:
    """Run kube-linter checks list and parse into catalog."""
    result = subprocess.run(
        [KUBE_LINTER_BIN, "checks", "list"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    catalog = []
    current: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Name:"):
            if current:
                name = current.get("name", "")
                current["severity"] = _map_severity(name)
                current["category"] = _map_category(name)
                catalog.append(current)
            current = {"name": line[len("Name:"):].strip()}
        elif line.startswith("Description:"):
            current["description"] = line[len("Description:"):].strip()
        elif line.startswith("Remediation:"):
            current["remediation"] = line[len("Remediation:"):].strip()
        elif line.startswith("Template:"):
            current["template"] = line[len("Template:"):].strip()
        elif line.startswith("Enabled by default:"):
            current["enabled_by_default"] = line[len("Enabled by default:"):].strip() == "true"
    if current:
        name = current.get("name", "")
        current["severity"] = _map_severity(name)
        current["category"] = _map_category(name)
        catalog.append(current)
    return catalog


def _summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "info": 0}
    by_cat: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "low")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        cat = f.get("category", "config")
        by_cat[cat] = by_cat.get(cat, 0) + 1
    return {
        "total_findings": len(findings),
        "by_severity": by_sev,
        "by_category": by_cat,
    }


LANDING_HTML = b"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>k8s-manifest-audit -- MCP server</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 680px; margin: 60px auto; padding: 0 24px; line-height: 1.55;
         color: #1a1a1a; background: #fafafa; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem 0; }
  .sub { color: #666; margin: 0 0 2rem 0; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
              background: #efefef; padding: 2px 6px; border-radius: 3px; font-size: .9rem; }
  pre { padding: 12px; overflow-x: auto; }
  a { color: #0366d6; text-decoration: none; }
  a:hover { text-decoration: underline; }
  footer { margin-top: 3rem; font-size: .85rem; color: #888; }
  ul { padding-left: 1.2rem; } li { margin: .35rem 0; }
</style>
</head>
<body>
<h1>k8s-manifest-audit -- MCP server</h1>
<p class="sub">Static audit of Kubernetes manifests powered by kube-linter.</p>
<p>Point your MCP client at the <code>/mcp</code> path on this host:</p>
<pre>POST /mcp     (Streamable HTTP transport)</pre>
<p>63 checks across security, resources, availability, network, RBAC, images, and config.</p>
<ul>
  <li><a href="https://apify.com/unbearable_dev/k8s-manifest-audit">Apify Store listing</a></li>
  <li><a href="https://modelcontextprotocol.io/clients">MCP client list</a></li>
</ul>
<footer>Built by Noel @ Unbearable TechTips. Part of the audit shop family:
<a href="https://apify.com/unbearable_dev/docker-compose-audit">docker-compose-audit</a>,
<a href="https://apify.com/unbearable_dev/dockerfile-audit">dockerfile-audit</a>,
<a href="https://apify.com/unbearable_dev/github-actions-audit">github-actions-audit</a>.
</footer>
</body>
</html>
"""


def get_server() -> FastMCP:
    server = FastMCP("k8s-manifest-audit", "0.1.0")

    @server.tool(annotations=_ANNOTATIONS)
    async def audit_manifest(
        manifest_content: str | None = None,
        yaml_content: str | None = None,
    ) -> dict[str, Any]:
        """Audit a single Kubernetes manifest (YAML string) with kube-linter.

        Runs all 31 default kube-linter checks against the provided YAML. Returns
        a findings array with severity, check ID, message, remediation hint, and
        object location (kind/name/namespace).

        Args:
            manifest_content: The full YAML content of one or more Kubernetes manifests
                              (may contain multiple documents separated by ---). Primary param.
            yaml_content: Deprecated alias for manifest_content. Accepted for one release cycle.
        """
        if manifest_content and yaml_content:
            return {
                "type": "text",
                "text": "Audit failed: Provide manifest_content or yaml_content (alias), not both.",
                "structuredContent": {"error": "Provide manifest_content or yaml_content (alias), not both.", "findings": []},
            }
        resolved_content = manifest_content or yaml_content
        if not resolved_content:
            return {
                "type": "text",
                "text": "Audit failed: Provide manifest_content (or yaml_content alias).",
                "structuredContent": {"error": "Provide manifest_content (or yaml_content alias).", "findings": []},
            }
        await Actor.charge("audit-call")
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(resolved_content)
            tmp_path = f.name
        try:
            data, _rc = _run_kube_linter(tmp_path)
        finally:
            os.unlink(tmp_path)

        reports = data.get("Reports") or []
        findings = _reports_to_findings(reports)
        summary = _summarize(findings)
        Actor.log.info(
            f"audit_manifest: {summary['total_findings']} findings "
            f"({summary['by_severity']['high']} high, "
            f"{summary['by_severity']['medium']} medium, "
            f"{summary['by_severity']['low']} low)"
        )
        return {
            "type": "text",
            "text": (
                f"audit_manifest: {summary['total_findings']} findings "
                f"({summary['by_severity']['high']} high, "
                f"{summary['by_severity']['medium']} medium, "
                f"{summary['by_severity']['low']} low, "
                f"{summary['by_severity']['info']} info)."
            ),
            "structuredContent": {
                "summary": summary,
                "findings": findings,
            },
        }

    @server.tool(annotations=_ANNOTATIONS)
    async def audit_directory(files: dict[str, str]) -> dict[str, Any]:
        """Audit multiple Kubernetes manifest files at once.

        Provide a dict mapping filename -> YAML content. All files are written to a
        temporary directory and linted together, so cross-file checks (dangling Service,
        mismatching selector, etc.) work correctly.

        Args:
            files: Dict mapping filename (e.g. "deployment.yaml") to YAML content string.
                   Filenames are used only for identifying findings in the output.
        """
        await Actor.charge("audit-call")
        with tempfile.TemporaryDirectory() as tmpdir:
            for filename, content in files.items():
                safe_name = os.path.basename(filename) or "manifest.yaml"
                dest = os.path.join(tmpdir, safe_name)
                with open(dest, "w") as f:
                    f.write(content)
            data, _rc = _run_kube_linter(tmpdir)

        reports = data.get("Reports") or []
        findings = _reports_to_findings(reports)
        summary = _summarize(findings)
        Actor.log.info(
            f"audit_directory: {len(files)} files, {summary['total_findings']} findings"
        )
        return {
            "type": "text",
            "text": (
                f"audit_directory: {len(files)} files, {summary['total_findings']} findings "
                f"({summary['by_severity']['high']} high, "
                f"{summary['by_severity']['medium']} medium, "
                f"{summary['by_severity']['low']} low, "
                f"{summary['by_severity']['info']} info)."
            ),
            "structuredContent": {
                "summary": summary,
                "findings": findings,
                "files_audited": list(files.keys()),
            },
        }

    @server.tool(annotations=_ANNOTATIONS)
    async def list_checks(enabled_only: bool = False) -> dict[str, Any]:
        """Return the full kube-linter check catalog (63 checks).

        Args:
            enabled_only: If True, return only checks enabled by default (31 checks).
                          If False (default), return all 63 checks.
        """
        await Actor.charge("list-checks")
        catalog = _get_checks_catalog()
        if enabled_only:
            catalog = [c for c in catalog if c.get("enabled_by_default")]
        categories = sorted({c.get("category", "config") for c in catalog})
        return {
            "type": "text",
            "text": f"{len(catalog)} checks across {len(categories)} categories.",
            "structuredContent": {
                "categories": categories,
                "total_checks": len(catalog),
                "checks": catalog,
            },
        }

    @server.tool(annotations=_ANNOTATIONS)
    async def explain_check(check_id: str) -> dict[str, Any]:
        """Return detailed information about a single kube-linter check.

        Args:
            check_id: The kube-linter check name, e.g. 'privileged-container',
                      'unset-cpu-requirements', 'latest-tag'. Use list_checks to
                      discover available check IDs.
        """
        await Actor.charge("list-checks")
        catalog = _get_checks_catalog()
        match = next((c for c in catalog if c.get("name") == check_id), None)
        if match is None:
            available = [c["name"] for c in catalog]
            return {
                "type": "text",
                "text": f"Check '{check_id}' not found. Use list_checks to see available check IDs.",
                "structuredContent": {
                    "error": f"unknown check: {check_id}",
                    "available_checks": available,
                },
            }
        return {
            "type": "text",
            "text": f"{check_id}: {match.get('description', '')}",
            "structuredContent": match,
        }

    @server.resource(
        uri="https://unbearabletechtips.com/k8s-manifest-audit",
        name="about",
    )
    def about() -> str:
        catalog = _get_checks_catalog()
        cats = sorted({c.get("category", "config") for c in catalog})
        return (
            "k8s-manifest-audit -- MCP server by Unbearable TechTips.\n"
            "Static audit of Kubernetes manifests powered by kube-linter.\n\n"
            f"Total checks: {len(catalog)} ({sum(1 for c in catalog if c.get('enabled_by_default'))} enabled by default)\n"
            f"Categories: {', '.join(cats)}\n\n"
            "Pricing: pay-per-event ($0.02 per audit, $0.005 for catalog discovery)."
        )

    return server


# ── Session middleware (same pattern as docker-compose-audit / dockerfile-audit) ──

def get_session_id(headers: Mapping[str, str]) -> str | None:
    for key in ("mcp-session-id", "mcp_session_id"):
        if value := headers.get(key):
            return value
    return None


class SessionTrackingMiddleware:
    def __init__(self, app: Any, port: int, timeout_secs: int) -> None:
        self.app = app
        self.port = port
        self.timeout_secs = timeout_secs
        self._last_activity: dict[str, float] = {}
        self._timers: dict[str, asyncio.Task[None]] = {}

    def _session_cleanup(self, sid: str) -> None:
        self._last_activity.pop(sid, None)
        if (timer := self._timers.pop(sid, None)) and not timer.done():
            timer.cancel()

    def _touch(self, sid: str) -> None:
        self._last_activity[sid] = time.time()
        if (timer := self._timers.get(sid)) and not timer.done():
            timer.cancel()

        async def close_if_idle() -> None:
            try:
                await asyncio.sleep(self.timeout_secs)
                elapsed = time.time() - self._last_activity.get(sid, 0)
                if elapsed < self.timeout_secs * 0.9:
                    return
                Actor.log.info(f"Closing idle session: {sid}")
                scope: Scope = {
                    "type": "http", "http_version": "1.1", "method": "DELETE",
                    "scheme": "http", "path": "/mcp", "raw_path": b"/mcp",
                    "query_string": b"",
                    "headers": [(b"mcp-session-id", sid.encode())],
                    "server": ("127.0.0.1", self.port),
                    "client": ("127.0.0.1", 0),
                    "_idle_close": True,
                }
                async def noop_receive(): return {"type": "http.request", "body": b"", "more_body": False}
                async def noop_send(_): pass
                await self(scope, noop_receive, noop_send)
                self._session_cleanup(sid)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                Actor.log.exception(f"Failed to close idle session {sid}: {e}")

        self._timers[sid] = asyncio.create_task(close_if_idle())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")

        if (scope.get("type") == "http" and scope.get("method") == "GET" and path in ("", "/")):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"cache-control", b"public, max-age=3600"),
                ],
            })
            await send({"type": "http.response.body", "body": LANDING_HTML})
            return

        if scope.get("type") != "http" or path not in ("/mcp", "/mcp/"):
            await self.app(scope, receive, send)
            return

        if scope.get("_idle_close"):
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        sid = get_session_id(request.headers)
        is_delete = scope.get("method") == "DELETE"

        if sid and not is_delete:
            self._touch(sid)

        new_sid: str | None = None

        async def capture_send(msg: MutableMapping[str, Any]) -> None:
            nonlocal new_sid
            if msg.get("type") == "http.response.start":
                for k, v in msg.get("headers", []):
                    if k.decode().lower() == "mcp-session-id":
                        new_sid = v.decode()
                        break
            await send(msg)

        await self.app(scope, receive, capture_send)

        if not sid and new_sid:
            Actor.log.info(f"New session: {new_sid}")
            self._touch(new_sid)

        if is_delete and sid:
            Actor.log.info(f"Session closed: {sid}")
            self._session_cleanup(sid)


async def main() -> None:
    await Actor.init()
    port = int(os.environ.get("APIFY_CONTAINER_PORT", "3000"))
    timeout_secs = int(os.environ.get("SESSION_TIMEOUT_SECS", "300"))

    server = get_server()
    app = server.http_app(transport="streamable-http")
    app = SessionTrackingMiddleware(app=app, port=port, timeout_secs=timeout_secs)

    try:
        Actor.log.info(
            f"Starting k8s-manifest-audit on port {port} (session timeout: {timeout_secs}s)"
        )
        config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")  # noqa: S104
        await uvicorn.Server(config).serve()
    except KeyboardInterrupt:
        Actor.log.info("Shutting down...")
    except Exception as e:
        Actor.log.error(f"Server failed: {e}")
        raise
