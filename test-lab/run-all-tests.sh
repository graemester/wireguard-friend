#!/bin/bash
#
# WireGuard Friend - Comprehensive Test Runner
# Just-add-water: ./test-lab/run-all-tests.sh
#
# Usage:
#   ./test-lab/run-all-tests.sh          # Unit/integration tests only
#   ./test-lab/run-all-tests.sh --docker # Include Docker network tests (starts/stops daemon)
#
# Runs all test suites and reports results.
# Exit code 0 = all tests passed, non-zero = failures detected.
#

set -e

RUN_DOCKER=false
DOCKER_WAS_RUNNING=false
if [ "$1" = "--docker" ] || [ "$1" = "-d" ]; then
    RUN_DOCKER=true
fi

# Docker daemon management functions
start_docker_if_needed() {
    if systemctl is-active --quiet docker 2>/dev/null; then
        DOCKER_WAS_RUNNING=true
        echo -e "${CYAN}[Docker]${NC} Daemon already running"
    else
        echo -e "${CYAN}[Docker]${NC} Starting daemon..."
        if sudo systemctl start docker 2>/dev/null; then
            echo -e "${CYAN}[Docker]${NC} Daemon started"
            sleep 2  # Give daemon time to initialize
        else
            echo -e "${RED}[Docker]${NC} Failed to start daemon (try: sudo systemctl start docker)"
            return 1
        fi
    fi
}

stop_docker_if_we_started_it() {
    if [ "$DOCKER_WAS_RUNNING" = false ]; then
        echo -e "${CYAN}[Docker]${NC} Stopping daemon..."
        sudo systemctl stop docker 2>/dev/null || true
        echo -e "${CYAN}[Docker]${NC} Daemon stopped"
    else
        echo -e "${CYAN}[Docker]${NC} Leaving daemon running (was already active)"
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

export PYTHONPATH="$PROJECT_ROOT"

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}  WireGuard Friend - Test Suite${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""
echo "Project: $PROJECT_ROOT"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

TOTAL_PASSED=0
TOTAL_FAILED=0
FAILED_SUITES=""

count_markers() {
    # Count occurrences of a pattern in text, return clean integer
    local text="$1"
    local pattern="$2"
    local count
    count=$(echo "$text" | grep -o "$pattern" | wc -l)
    echo "$count" | tr -d ' \n\r'
}

run_test_suite() {
    local name="$1"
    local script="$2"

    echo -e "${CYAN}[$name]${NC} Running..."

    local output
    local exit_code=0
    output=$(python3 "$script" 2>&1) || exit_code=$?

    # Count passes and fails using multiple patterns
    local pass_count=0
    local fail_count=0

    # Try [PASS]/[FAIL] format first
    local p1=$(count_markers "$output" '\[PASS\]')
    local f1=$(count_markers "$output" '\[FAIL\]')

    # Try checkmark format
    local p2=$(count_markers "$output" '✓')
    local f2=$(count_markers "$output" '✗')

    # Pick the format that has results
    if [ "$p1" -gt 0 ] 2>/dev/null || [ "$f1" -gt 0 ] 2>/dev/null; then
        pass_count=$p1
        fail_count=$f1
    elif [ "$p2" -gt 0 ] 2>/dev/null || [ "$f2" -gt 0 ] 2>/dev/null; then
        pass_count=$p2
        # For checkmark format, look for FAILED or ✗ separately
        fail_count=$(count_markers "$output" 'FAILED\|✗')
        # Exclude "FAILED" in summary lines, just count test failures
        if echo "$output" | grep -q "tests failed"; then
            fail_count=$(echo "$output" | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' | head -1)
        fi
    fi

    # Default to 0 if empty
    pass_count=${pass_count:-0}
    fail_count=${fail_count:-0}

    # Check if script itself failed (non-zero exit without proper test output)
    if [ "$exit_code" -ne 0 ] && [ "$pass_count" -eq 0 ] && [ "$fail_count" -eq 0 ]; then
        echo -e "${RED}[$name] ERROR${NC} - Script exited with code $exit_code"
        echo "$output" | tail -5
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
        FAILED_SUITES="$FAILED_SUITES $name"
        echo ""
        return
    fi

    # Report results
    if [ "$fail_count" -eq 0 ] 2>/dev/null; then
        echo -e "${GREEN}[$name] PASSED${NC} ($pass_count tests)"
    else
        echo -e "${RED}[$name] FAILED${NC} ($pass_count passed, $fail_count failed)"
        FAILED_SUITES="$FAILED_SUITES $name"
    fi

    TOTAL_PASSED=$((TOTAL_PASSED + pass_count))
    TOTAL_FAILED=$((TOTAL_FAILED + fail_count))
    echo ""
}

# Run all test suites
echo -e "${BOLD}Running Test Suites...${NC}"
echo "----------------------------------------"
echo ""

run_test_suite "Comprehensive" "test-lab/test_comprehensive.py"
run_test_suite "Import Workflows" "test-lab/test_import_workflows.py"
run_test_suite "Extramural" "test-lab/test_extramural.py"
run_test_suite "Fidelity" "test-lab/test_fidelity.py"
run_test_suite "CLI Behavior" "test-lab/test_cli_behavior.py"

# Run existing v1 tests if they exist
if [ -f "v1/test_config_detector.py" ]; then
    run_test_suite "Config Detector" "v1/test_config_detector.py"
fi

if [ -f "v1/test_roundtrip.py" ]; then
    run_test_suite "Roundtrip" "v1/test_roundtrip.py"
fi

if [ -f "v1/test_extramural_e2e.py" ]; then
    run_test_suite "Extramural E2E" "v1/test_extramural_e2e.py"
fi

# Docker network tests (optional)
if [ "$RUN_DOCKER" = true ]; then
    echo -e "${BOLD}Docker Network Tests${NC}"
    echo "----------------------------------------"
    echo ""

    # Start Docker daemon if not running
    start_docker_if_needed || {
        echo -e "${RED}[Docker] FAILED${NC} - Could not start Docker daemon"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
        FAILED_SUITES="$FAILED_SUITES Docker"
        # Skip to summary
        RUN_DOCKER=false
    }

    if [ "$RUN_DOCKER" = true ]; then
        # Clean up any leftover root-owned config directories
        echo -e "${CYAN}[Docker]${NC} Preparing test environment..."
        rm -rf test-lab/configs/cs test-lab/configs/snr test-lab/configs/remote1 test-lab/configs/remote2 2>/dev/null || true

        # The Python test handles its own Docker lifecycle
        echo -e "${CYAN}[Docker]${NC} Running connectivity tests..."
        run_test_suite "Docker Connectivity" "test-lab/test_docker_connectivity.py"

        # Stop Docker daemon if we started it
        stop_docker_if_we_started_it
    fi
    echo ""
fi

# Summary
echo "========================================"
echo -e "${BOLD}SUMMARY${NC}"
echo "========================================"
echo ""
echo -e "Total Passed: ${GREEN}$TOTAL_PASSED${NC}"
echo -e "Total Failed: ${RED}$TOTAL_FAILED${NC}"
if [ "$RUN_DOCKER" = false ]; then
    echo -e "(Docker tests skipped - use --docker to include)"
fi
echo ""

if [ "$TOTAL_FAILED" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}FAILURES DETECTED${NC}"
    echo "Failed suites:$FAILED_SUITES"
    exit 1
fi
