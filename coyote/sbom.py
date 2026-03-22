"""CycloneDX SBOM generation for Coyote.

Generates a CycloneDX v1.5 JSON Software Bill of Materials from
dependency lockfiles/manifests. Pure component inventory — no
vulnerability data.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

from . import __version__
from .deps import DependencyCoordinate, collect_dependencies

_ECOSYSTEM_TO_PURL_TYPE = {
    "pypi": "pypi",
    "npm": "npm",
    "go": "golang",
    "cratesio": "cargo",
}


def _normalize_pypi_name(name: str) -> str:
    """Normalize a PyPI package name for PURL (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _encode_npm_scope(name: str) -> str:
    """Percent-encode the ``@`` in scoped npm package names for PURL."""
    if name.startswith("@"):
        return "%40" + name[1:]
    return name


def _purl_for_dependency(dep: DependencyCoordinate) -> str | None:
    """Build a Package URL string for a dependency coordinate."""
    purl_type = _ECOSYSTEM_TO_PURL_TYPE.get(dep.ecosystem)
    if purl_type is None:
        return None

    if purl_type == "pypi":
        pkg_name = _normalize_pypi_name(dep.name)
    elif purl_type == "npm":
        pkg_name = _encode_npm_scope(dep.name)
    else:
        pkg_name = dep.name

    return f"pkg:{purl_type}/{pkg_name}@{dep.version}"


def generate_sbom(repo_path: str, *, include_dev: bool = False) -> dict:
    """Generate a CycloneDX v1.5 JSON SBOM for the given repository.

    Returns the SBOM as a plain dict ready for ``json.dumps``.
    """
    dependencies = collect_dependencies(repo_path, include_dev=include_dev)

    components = []
    for dep in sorted(dependencies, key=lambda d: (d.ecosystem, d.name, d.version)):
        purl = _purl_for_dependency(dep)
        scope = "optional" if dep.is_dev_dependency else "required"
        component: dict = {
            "type": "library",
            "name": dep.name,
            "version": dep.version,
            "scope": scope,
            "properties": [
                {"name": "coyote:ecosystem", "value": dep.ecosystem},
                {"name": "coyote:manifest", "value": dep.manifest_path},
                {
                    "name": "coyote:directDependency",
                    "value": str(dep.is_direct_dependency).lower()
                    if dep.is_direct_dependency is not None
                    else "unknown",
                },
            ],
        }
        if purl is not None:
            component["purl"] = purl
        components.append(component)

    repo_name = os.path.basename(os.path.abspath(repo_path)) or "unknown"

    sbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "Coyote",
                    "name": "coyote",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": repo_name,
            },
        },
        "components": components,
    }

    return sbom


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coyote sbom",
        description="Generate a CycloneDX v1.5 JSON SBOM from dependency manifests.",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Path to the repository to scan (default: current directory).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write SBOM to FILE instead of stdout (convention: .cdx.json).",
    )
    parser.add_argument(
        "--include-dev",
        action="store_true",
        default=False,
        help="Include development dependencies (excluded by default).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``coyote sbom``."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    sbom = generate_sbom(args.repo, include_dev=args.include_dev)
    payload = json.dumps(sbom, indent=2) + "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"SBOM written to {args.output} ({len(sbom['components'])} components)")
    else:
        sys.stdout.write(payload)

    return 0
