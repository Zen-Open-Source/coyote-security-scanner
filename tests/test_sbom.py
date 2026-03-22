"""Tests for CycloneDX SBOM generation."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from coyote.deps import DependencyCoordinate, collect_dependencies
from coyote.sbom import (
    _encode_npm_scope,
    _normalize_pypi_name,
    _purl_for_dependency,
    generate_sbom,
    main as sbom_main,
)


class TestSbomFromRequirementsTxt(unittest.TestCase):
    """requirements.txt with 2 pinned packages → 2 components with correct PURLs."""

    def test_sbom_from_requirements_txt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "requirements.txt").write_text(
                "requests==2.31.0\nflask==3.0.0\n", encoding="utf-8"
            )

            sbom = generate_sbom(tmp)

            self.assertEqual("CycloneDX", sbom["bomFormat"])
            self.assertEqual("1.5", sbom["specVersion"])
            self.assertEqual(2, len(sbom["components"]))

            names = {c["name"] for c in sbom["components"]}
            self.assertEqual({"requests", "flask"}, names)

            for comp in sbom["components"]:
                self.assertIn("purl", comp)
                self.assertTrue(comp["purl"].startswith("pkg:pypi/"))


class TestSbomExcludesDevByDefault(unittest.TestCase):
    """poetry.lock with main + dev deps → only main appears by default."""

    def test_sbom_excludes_dev_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "poetry.lock").write_text(
                """\
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
""",
                encoding="utf-8",
            )

            sbom = generate_sbom(tmp, include_dev=False)

            comp_names = [c["name"] for c in sbom["components"]]
            self.assertIn("requests", comp_names)
            self.assertNotIn("pytest", comp_names)


class TestSbomIncludesDevWhenFlagSet(unittest.TestCase):
    """Both main and dev deps appear with include_dev=True, dev has scope optional."""

    def test_sbom_includes_dev_when_flag_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "poetry.lock").write_text(
                """\
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
""",
                encoding="utf-8",
            )

            sbom = generate_sbom(tmp, include_dev=True)

            comp_names = [c["name"] for c in sbom["components"]]
            self.assertIn("requests", comp_names)
            self.assertIn("pytest", comp_names)

            dev_comp = next(c for c in sbom["components"] if c["name"] == "pytest")
            self.assertEqual("optional", dev_comp["scope"])

            main_comp = next(c for c in sbom["components"] if c["name"] == "requests")
            self.assertEqual("required", main_comp["scope"])


class TestPurlNpmScoped(unittest.TestCase):
    """Scoped npm package @scope/pkg encodes @ as %40 in PURL."""

    def test_purl_npm_scoped(self) -> None:
        dep = DependencyCoordinate(
            ecosystem="npm",
            name="@angular/core",
            version="17.0.0",
            manifest_path="package-lock.json",
        )
        purl = _purl_for_dependency(dep)
        self.assertEqual("pkg:npm/%40angular/core@17.0.0", purl)


class TestPurlPypiNormalization(unittest.TestCase):
    """PyPI names with underscores/dots are normalized to hyphens."""

    def test_purl_pypi_normalization(self) -> None:
        dep = DependencyCoordinate(
            ecosystem="pypi",
            name="my_cool.package",
            version="1.0.0",
            manifest_path="requirements.txt",
        )
        purl = _purl_for_dependency(dep)
        self.assertEqual("pkg:pypi/my-cool-package@1.0.0", purl)

    def test_normalize_pypi_name_underscores(self) -> None:
        self.assertEqual("my-cool-package", _normalize_pypi_name("my_cool_package"))

    def test_normalize_pypi_name_dots(self) -> None:
        self.assertEqual("my-package", _normalize_pypi_name("my.package"))

    def test_normalize_pypi_name_mixed(self) -> None:
        self.assertEqual("a-b-c", _normalize_pypi_name("a_b.c"))


class TestPurlGolang(unittest.TestCase):
    """Go module full path is preserved verbatim in PURL."""

    def test_purl_golang(self) -> None:
        dep = DependencyCoordinate(
            ecosystem="go",
            name="github.com/gin-gonic/gin",
            version="1.9.1",
            manifest_path="go.mod",
        )
        purl = _purl_for_dependency(dep)
        self.assertEqual("pkg:golang/github.com/gin-gonic/gin@1.9.1", purl)


class TestPurlCargo(unittest.TestCase):
    """Cargo ecosystem maps to pkg:cargo/ PURL type."""

    def test_purl_cargo(self) -> None:
        dep = DependencyCoordinate(
            ecosystem="cratesio",
            name="serde",
            version="1.0.193",
            manifest_path="Cargo.lock",
        )
        purl = _purl_for_dependency(dep)
        self.assertEqual("pkg:cargo/serde@1.0.193", purl)


class TestSbomOutputToFile(unittest.TestCase):
    """CLI --output flag writes valid JSON to the specified file."""

    def test_sbom_output_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "requirements.txt").write_text(
                "requests==2.31.0\n", encoding="utf-8"
            )
            output_file = str(base / "bom.cdx.json")

            rc = sbom_main(["--repo", tmp, "--output", output_file])

            self.assertEqual(0, rc)
            with open(output_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual("CycloneDX", data["bomFormat"])
            self.assertEqual(1, len(data["components"]))


class TestSbomSerialNumberFormat(unittest.TestCase):
    """serialNumber matches urn:uuid:{uuid4}."""

    def test_sbom_serial_number_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sbom = generate_sbom(tmp)
            self.assertTrue(
                re.match(
                    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    sbom["serialNumber"],
                ),
                f"serialNumber did not match UUID format: {sbom['serialNumber']}",
            )


class TestSbomEmptyRepo(unittest.TestCase):
    """No lockfiles → empty components list, valid structure."""

    def test_sbom_empty_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sbom = generate_sbom(tmp)

            self.assertEqual("CycloneDX", sbom["bomFormat"])
            self.assertEqual("1.5", sbom["specVersion"])
            self.assertEqual(1, sbom["version"])
            self.assertIsInstance(sbom["components"], list)
            self.assertEqual(0, len(sbom["components"]))
            self.assertIn("metadata", sbom)
            self.assertIn("timestamp", sbom["metadata"])
            self.assertIn("tools", sbom["metadata"])
            self.assertIn("component", sbom["metadata"])


class TestSbomComponentProperties(unittest.TestCase):
    """Components carry coyote:ecosystem and coyote:manifest properties."""

    def test_sbom_component_properties(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "requirements.txt").write_text(
                "flask==3.0.0\n", encoding="utf-8"
            )

            sbom = generate_sbom(tmp)
            self.assertEqual(1, len(sbom["components"]))

            comp = sbom["components"][0]
            props = {p["name"]: p["value"] for p in comp["properties"]}
            self.assertEqual("pypi", props["coyote:ecosystem"])
            self.assertEqual("requirements.txt", props["coyote:manifest"])
            self.assertIn("coyote:directDependency", props)


class TestCollectDependenciesApi(unittest.TestCase):
    """collect_dependencies() returns DependencyCoordinate instances."""

    def test_collect_dependencies_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "requirements.txt").write_text(
                "requests==2.31.0\nflask==3.0.0\n", encoding="utf-8"
            )

            deps = collect_dependencies(tmp)

            self.assertIsInstance(deps, list)
            self.assertEqual(2, len(deps))
            for dep in deps:
                self.assertIsInstance(dep, DependencyCoordinate)

            names = {d.name for d in deps}
            self.assertEqual({"requests", "flask"}, names)


if __name__ == "__main__":
    unittest.main()
