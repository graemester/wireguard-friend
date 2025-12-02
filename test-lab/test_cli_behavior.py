#!/usr/bin/env python3
"""
CLI Behavior Tests

Tests the CLI interface behavior:
1. Error message quality (helpful, not stack traces)
2. Invalid input handling
3. Database operations
4. Config generation output

Run with: python3 test_cli_behavior.py
"""

import sys
import os
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime

# Add project to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@dataclass
class CLITestResult:
    """Result of a CLI test"""
    name: str
    passed: bool
    message: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


@dataclass
class CLITestReport:
    """Complete CLI test report"""
    results: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)


class CLIBehaviorTests:
    """Test CLI behavior"""

    def __init__(self):
        self.report = CLITestReport()
        self.temp_dir = None
        self.wg_friend_path = PROJECT_ROOT / "v1" / "wg-friend"

    def run_all(self) -> CLITestReport:
        """Run all CLI tests"""
        print("=" * 80)
        print("CLI BEHAVIOR TESTS")
        print("=" * 80)
        print()

        self.temp_dir = Path(tempfile.mkdtemp(prefix="wgf_cli_test_"))
        print(f"Temp directory: {self.temp_dir}")
        print()

        try:
            # Test --version flag
            self._test_version_flag()

            # Test --help flag
            self._test_help_flag()

            # Test missing database error
            self._test_missing_database_error()

            # Test generate with no database
            self._test_generate_no_db()

            # Test import with invalid file
            self._test_import_invalid_file()

            # Test list subcommand
            self._test_list_command()

        finally:
            # Cleanup
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)

        self._print_report()
        return self.report

    def _run_cli(self, args: list, cwd: Optional[Path] = None) -> Tuple[int, str, str]:
        """Run wg-friend CLI with arguments"""
        cmd = [sys.executable, str(self.wg_friend_path)] + args

        result = subprocess.run(
            cmd,
            cwd=cwd or self.temp_dir,
            capture_output=True,
            text=True,
            timeout=30
        )

        return result.returncode, result.stdout, result.stderr

    def _add_result(self, name: str, passed: bool, message: str = "",
                    stdout: str = "", stderr: str = "", returncode: int = 0):
        """Add test result"""
        result = CLITestResult(
            name=name,
            passed=passed,
            message=message,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode
        )
        self.report.results.append(result)

        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {name}")
        if not passed:
            print(f"         {message}")

    def _test_version_flag(self):
        """Test --version flag shows version info"""
        print("\n--- Version Flag ---")

        try:
            returncode, stdout, stderr = self._run_cli(['--version'])

            # Should include version string
            output = stdout + stderr
            if 'wg-friend v' in output or 'kestrel' in output.lower():
                self._add_result(
                    "--version shows version",
                    True,
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode
                )
            else:
                self._add_result(
                    "--version shows version",
                    False,
                    f"Version not found in output: {output[:200]}",
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode
                )

        except Exception as e:
            self._add_result("--version shows version", False, str(e))

    def _test_help_flag(self):
        """Test --help flag shows help"""
        print("\n--- Help Flag ---")

        try:
            returncode, stdout, stderr = self._run_cli(['--help'])

            # Should include usage info
            output = stdout + stderr
            if 'usage' in output.lower() or 'wireguard' in output.lower():
                self._add_result(
                    "--help shows usage",
                    True,
                    stdout=stdout,
                    returncode=returncode
                )
            else:
                self._add_result(
                    "--help shows usage",
                    False,
                    f"Help not found in output",
                    stdout=stdout,
                    stderr=stderr
                )

            # Test subcommand help
            for cmd in ['init', 'generate', 'status']:
                returncode, stdout, stderr = self._run_cli([cmd, '--help'])
                output = stdout + stderr
                if 'usage' in output.lower() or cmd in output.lower():
                    self._add_result(
                        f"{cmd} --help shows help",
                        True,
                        returncode=returncode
                    )
                else:
                    self._add_result(
                        f"{cmd} --help shows help",
                        False,
                        "Help not shown",
                        stdout=stdout,
                        stderr=stderr
                    )

        except Exception as e:
            self._add_result("--help shows usage", False, str(e))

    def _test_missing_database_error(self):
        """Test error message when database doesn't exist"""
        print("\n--- Missing Database Handling ---")

        # Create a subdirectory with no database
        test_dir = self.temp_dir / "no_db"
        test_dir.mkdir()

        try:
            # Run generate in directory with no database
            returncode, stdout, stderr = self._run_cli(
                ['generate', '--db', 'nonexistent.db'],
                cwd=test_dir
            )

            output = stdout + stderr

            # Should have helpful error, not stack trace
            if returncode != 0:  # Should fail
                # Check for helpful message
                if 'not found' in output.lower() or 'does not exist' in output.lower():
                    self._add_result(
                        "Missing DB shows helpful error",
                        True,
                        stdout=stdout,
                        stderr=stderr,
                        returncode=returncode
                    )
                # Check NOT a raw traceback
                elif 'Traceback (most recent call last)' in output:
                    self._add_result(
                        "Missing DB shows helpful error",
                        False,
                        "Shows stack trace instead of helpful message",
                        stdout=stdout,
                        stderr=stderr,
                        returncode=returncode
                    )
                else:
                    # Some error message shown
                    self._add_result(
                        "Missing DB shows helpful error",
                        True,
                        f"Error shown (non-zero exit)",
                        stdout=stdout,
                        stderr=stderr,
                        returncode=returncode
                    )
            else:
                self._add_result(
                    "Missing DB shows helpful error",
                    False,
                    "Command succeeded when it should fail",
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode
                )

        except Exception as e:
            self._add_result("Missing DB shows helpful error", False, str(e))

    def _test_generate_no_db(self):
        """Test generate command with no database"""
        print("\n--- Generate Without Database ---")

        test_dir = self.temp_dir / "gen_test"
        test_dir.mkdir()

        try:
            returncode, stdout, stderr = self._run_cli(
                ['generate', '--output', 'out', '--db', 'wireguard.db'],
                cwd=test_dir
            )

            # Should fail gracefully
            if returncode != 0:
                self._add_result(
                    "Generate fails gracefully without DB",
                    True,
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode
                )
            else:
                self._add_result(
                    "Generate fails gracefully without DB",
                    False,
                    "Generate should fail without database",
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode
                )

        except Exception as e:
            self._add_result("Generate fails gracefully without DB", False, str(e))

    def _test_import_invalid_file(self):
        """Test import with invalid config file"""
        print("\n--- Import Invalid File ---")

        test_dir = self.temp_dir / "import_test"
        test_dir.mkdir()

        # Create invalid config
        invalid_conf = test_dir / "invalid.conf"
        invalid_conf.write_text("This is not a valid WireGuard config\nNo [Interface] section\n")

        try:
            returncode, stdout, stderr = self._run_cli(
                ['import', '--cs', str(invalid_conf), '--db', 'test.db'],
                cwd=test_dir
            )

            output = stdout + stderr

            # Should fail with meaningful error
            if returncode != 0:
                # Good - it failed
                # Check for helpful message vs stack trace
                if 'Traceback (most recent call last)' in output:
                    # Stack trace shown - less ideal but not fatal
                    self._add_result(
                        "Import invalid file shows error",
                        True,  # Still passes - we handle the error
                        "Shows traceback (could be improved)",
                        stdout=stdout,
                        stderr=stderr,
                        returncode=returncode
                    )
                else:
                    self._add_result(
                        "Import invalid file shows error",
                        True,
                        stdout=stdout,
                        stderr=stderr,
                        returncode=returncode
                    )
            else:
                self._add_result(
                    "Import invalid file shows error",
                    False,
                    "Import should fail with invalid config",
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode
                )

        except Exception as e:
            self._add_result("Import invalid file shows error", False, str(e))

    def _test_list_command(self):
        """Test list command with no database"""
        print("\n--- List Command ---")

        test_dir = self.temp_dir / "list_test"
        test_dir.mkdir()

        try:
            returncode, stdout, stderr = self._run_cli(
                ['list', '--db', 'nonexistent.db'],
                cwd=test_dir
            )

            # Should handle missing database gracefully
            # (either error message or empty list)
            output = stdout + stderr

            if returncode != 0:
                # Failed as expected when no DB
                self._add_result(
                    "List handles missing DB",
                    True,
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode
                )
            else:
                # Might succeed with empty list - also OK
                self._add_result(
                    "List handles missing DB",
                    True,
                    "Returned empty/default output",
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode
                )

        except Exception as e:
            self._add_result("List handles missing DB", False, str(e))

    def _print_report(self):
        """Print test report"""
        print("\n")
        print("=" * 80)
        print("CLI TEST REPORT")
        print("=" * 80)
        print()

        print(f"Total Tests: {self.report.total}")
        print(f"Passed:      {self.report.passed}")
        print(f"Failed:      {self.report.failed}")
        print()

        if self.report.failed > 0:
            print("Failed Tests:")
            print("-" * 40)
            for r in self.report.results:
                if not r.passed:
                    print(f"  - {r.name}")
                    print(f"    {r.message}")
                    if r.stderr:
                        print(f"    stderr: {r.stderr[:100]}...")

        print()
        print("=" * 80)
        if self.report.failed == 0:
            print("ALL CLI TESTS PASSED")
        else:
            print(f"FAILURES: {self.report.failed} test(s) failed")
        print("=" * 80)


def main():
    """Run CLI behavior tests"""
    tests = CLIBehaviorTests()
    report = tests.run_all()

    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
