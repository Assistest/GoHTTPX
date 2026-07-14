import unittest
from pathlib import Path


class ReleaseContractTests(unittest.TestCase):
    def test_publish_workflow_builds_before_dist_tests_and_validates_all_versions(self):
        root = Path(__file__).parent.parent
        workflow = (root / ".github" / "workflows" / "publish-release.yml").read_text(encoding="utf-8")
        build = workflow.index("- run: python -m build")
        tests = workflow.index('- run: python -B -m unittest discover -s python -p "test_*.py" -v')
        upload = workflow.index("- uses: actions/upload-artifact@v4")
        self.assertLess(build, tests)
        self.assertLess(tests, upload)
        self.assertIn("module_version", workflow)
        self.assertIn("python/gohttpx.py", workflow)
        self.assertNotIn("tomllib", workflow)
        self.assertIn("python -c 'import re", workflow)
        self.assertIn(r"(?=^\[|\Z)", workflow)
        self.assertIn(r"^version\s*=\s*", workflow)
        self.assertNotIn(r'\\"', workflow)
        self.assertIn('test "$version" = "$module_version"', workflow)
        self.assertIn("-X main.serverVersion=${{ needs.validate.outputs.version }}", workflow)

    def test_install_test_does_not_hardcode_dist_info_version(self):
        source = (Path(__file__).parent / "test_package_install.py").read_text(encoding="utf-8")
        self.assertNotIn("gohttpx-1.0.0.dist-info/METADATA", source)
        self.assertIn("*.dist-info/METADATA", source)


if __name__ == "__main__":
    unittest.main()
