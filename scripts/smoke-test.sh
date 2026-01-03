#!/bin/bash
set -e

echo "==================================="
echo "DeepGuard Smoke Tests"
echo "==================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_SAMPLES_DIR="$PROJECT_ROOT/test-samples/smoke-tests"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED_TESTS=0
PASSED_TESTS=0

# Test helper functions
test_directory_exists() {
    local dir=$1
    local lang=$2

    echo -n "  [${lang}] Checking test directory exists... "
    if [ -d "$dir" ]; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED_TESTS++))
        return 0
    else
        echo -e "${RED}FAIL${NC} - Directory not found: $dir"
        ((FAILED_TESTS++))
        return 1
    fi
}

test_files_exist() {
    local dir=$1
    local lang=$2
    local min_files=$3

    echo -n "  [${lang}] Checking test files exist... "
    file_count=$(find "$dir" -type f | wc -l | tr -d ' ')

    if [ "$file_count" -ge "$min_files" ]; then
        echo -e "${GREEN}PASS${NC} - Found $file_count files"
        ((PASSED_TESTS++))
        return 0
    else
        echo -e "${RED}FAIL${NC} - Expected at least $min_files files, found $file_count"
        ((FAILED_TESTS++))
        return 1
    fi
}

test_file_contains_pattern() {
    local file=$1
    local pattern=$2
    local lang=$3
    local description=$4

    echo -n "  [${lang}] Checking for $description... "
    if grep -q "$pattern" "$file"; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED_TESTS++))
        return 0
    else
        echo -e "${RED}FAIL${NC} - Pattern not found: $pattern"
        ((FAILED_TESTS++))
        return 1
    fi
}

# Test 1: JavaScript/TypeScript samples
echo "Test Suite: JavaScript/TypeScript Smoke Tests"
echo "---------------------------------------"

JS_TS_DIR="$TEST_SAMPLES_DIR/js-ts"
test_directory_exists "$JS_TS_DIR" "JS/TS"
test_files_exist "$JS_TS_DIR" "JS/TS" 2

if [ -f "$JS_TS_DIR/vulnerable-api.js" ]; then
    test_file_contains_pattern "$JS_TS_DIR/vulnerable-api.js" "SELECT.*FROM.*WHERE.*=" "JS/TS" "SQL injection pattern"
    test_file_contains_pattern "$JS_TS_DIR/vulnerable-api.js" "\${searchTerm}" "JS/TS" "XSS pattern"
fi

if [ -f "$JS_TS_DIR/auth.ts" ]; then
    test_file_contains_pattern "$JS_TS_DIR/auth.ts" "md5" "JS/TS" "weak crypto pattern"
    test_file_contains_pattern "$JS_TS_DIR/auth.ts" "super-secret" "JS/TS" "hardcoded secret"
fi

echo ""

# Test 2: Python samples
echo "Test Suite: Python Smoke Tests"
echo "---------------------------------------"

PYTHON_DIR="$TEST_SAMPLES_DIR/python"
test_directory_exists "$PYTHON_DIR" "Python"
test_files_exist "$PYTHON_DIR" "Python" 2

if [ -f "$PYTHON_DIR/api.py" ]; then
    test_file_contains_pattern "$PYTHON_DIR/api.py" "execute.*query" "Python" "SQL injection pattern"
    test_file_contains_pattern "$PYTHON_DIR/api.py" "os.path.join" "Python" "path traversal pattern"
    test_file_contains_pattern "$PYTHON_DIR/api.py" "os.popen" "Python" "command injection pattern"
fi

if [ -f "$PYTHON_DIR/auth.py" ]; then
    test_file_contains_pattern "$PYTHON_DIR/auth.py" "hashlib.md5" "Python" "weak crypto pattern"
    test_file_contains_pattern "$PYTHON_DIR/auth.py" "pickle.loads" "Python" "insecure deserialization"
    test_file_contains_pattern "$PYTHON_DIR/auth.py" "DB_PASSWORD.*=" "Python" "hardcoded credentials"
fi

echo ""

# Test 3: Java samples
echo "Test Suite: Java Smoke Tests"
echo "---------------------------------------"

JAVA_DIR="$TEST_SAMPLES_DIR/java"
test_directory_exists "$JAVA_DIR" "Java"
test_files_exist "$JAVA_DIR" "Java" 2

if [ -f "$JAVA_DIR/UserController.java" ]; then
    test_file_contains_pattern "$JAVA_DIR/UserController.java" "executeQuery.*query" "Java" "SQL injection pattern"
    test_file_contains_pattern "$JAVA_DIR/UserController.java" "DB_PASSWORD.*=" "Java" "hardcoded credentials"
fi

if [ -f "$JAVA_DIR/AuthService.java" ]; then
    test_file_contains_pattern "$JAVA_DIR/AuthService.java" "MD5" "Java" "weak crypto pattern"
    test_file_contains_pattern "$JAVA_DIR/AuthService.java" "ObjectInputStream" "Java" "insecure deserialization"
    test_file_contains_pattern "$JAVA_DIR/AuthService.java" "API_KEY.*=" "Java" "hardcoded API key"
fi

echo ""
echo "==================================="
echo "Smoke Test Summary"
echo "==================================="
echo -e "Passed: ${GREEN}${PASSED_TESTS}${NC}"
echo -e "Failed: ${RED}${FAILED_TESTS}${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ All smoke tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some smoke tests failed${NC}"
    exit 1
fi
