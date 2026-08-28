import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("gohttpx_release", Path(__file__).resolve().parents[1] / "tools" / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseContractTests(unittest.TestCase):
    def test_publish_workflow_builds_before_dist_tests_and_validates_all_versions(self):
        root = Path(__file__).parent.parent
        workflow = (root / ".github" / "workflows" / "publish-release.yml").read_text(encoding="utf-8")
        build = workflow.index("- run: python -m build")
        tests = workflow.index('- run: python -B -m unittest discover -s python -p "test_*.py" -v')
        upload = workflow.index("- uses: actions/upload-artifact@v4")
        self.assertLess(build, tests)
        self.assertLess(tests, upload)
        self.assertIn("runs-on: windows-latest", workflow)
        self.assertIn("python tools/release.py validate", workflow)
        self.assertIn("go test -race ./...", workflow)
        self.assertIn("python tools/release.py binary", workflow)
        script = (root / "tools" / "release.py").read_text(encoding="utf-8")
        self.assertIn("package_version != module_version", script)
        self.assertIn("package_version != server_version", script)
        self.assertIn('tag != "v" + package_version', script)
        self.assertIn("-X main.serverVersion={version}", script)
        self.assertIn('gh release create "${GITHUB_REF_NAME}" release-assets/* --repo "$GITHUB_REPOSITORY"', workflow)

    def test_install_test_does_not_hardcode_dist_info_version(self):
        source = (Path(__file__).parent / "test_package_install.py").read_text(encoding="utf-8")
        self.assertNotIn("gohttpx-1.0.0.dist-info/METADATA", source)
        self.assertIn("*.dist-info/METADATA", source)

    def test_release_binary_requires_exact_clean_revision_and_platform(self):
        revision = "a" * 40
        metadata = f"\tbuild\tvcs.revision={revision}\n\tbuild\tvcs.modified=false\n\tbuild\tGOOS=windows\n\tbuild\tGOARCH=amd64\n"
        for invalid in (
            metadata.replace(revision, "b" * 40),
            metadata.replace("vcs.modified=false", "vcs.modified=true"),
            metadata.replace("GOOS=windows", "GOOS=linux"),
            metadata.replace("GOARCH=amd64", "GOARCH=arm64"),
            "",
        ):
            with self.subTest(metadata=invalid), patch.object(release.subprocess, "run", return_value=SimpleNamespace(stdout=invalid)):
                with self.assertRaises(ValueError):
                    release.verify_binary(Path("server.exe"), "2.0.0", revision)

    def test_release_binary_checks_executable_version_after_build_metadata(self):
        revision = "a" * 40
        metadata = f"\tbuild\tvcs.revision={revision}\n\tbuild\tvcs.modified=false\n\tbuild\tGOOS=windows\n\tbuild\tGOARCH=amd64\n"
        for version, valid in (("2.0.0", True), ("1.0.2", False)):
            outputs = [SimpleNamespace(stdout=metadata), SimpleNamespace(stdout=f"GoHTTPX server {version} protocol 1 req/v3 v3.59.0 uTLS v1.8.2\n")]
            with self.subTest(version=version), patch.object(release.subprocess, "run", side_effect=outputs) as run:
                if valid:
                    release.verify_binary(Path("server.exe"), "2.0.0", revision)
                    self.assertEqual(run.call_count, 2)
                else:
                    with self.assertRaises(ValueError):
                        release.verify_binary(Path("server.exe"), "2.0.0", revision)

    def test_release_notes_reject_uncommitted_source_before_reading_artifacts(self):
        with patch.object(release.subprocess, "run", return_value=SimpleNamespace(stdout=" M api.go\n")) as run:
            with self.assertRaises(ValueError):
                release.write_release_notes("2.0.0")
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
