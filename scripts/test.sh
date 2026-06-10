#!/usr/bin/env bash
set -euo pipefail

MODULE_NAME="rootwriters"
TEST_FILE="/tmp/rootwriters_test_file"
CONFIG_DIR="/etc/fsc"
CONFIG_FILE="${CONFIG_DIR}/rootwriters"

if [ "$EUID" -eq 0 ] && [ -z "${SUDO_USER:-}" ]; then
    echo "[!] Run this script as a normal user with sudo access, not as root"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_UID="$(id -u "${REAL_USER}")"

if ! command -v sudo >/dev/null 2>&1; then
    echo "[!] sudo not found"
    exit 1
fi

sudo -v

if ! lsmod | awk '{print $1}' | grep -qx "${MODULE_NAME}"; then
    echo "[!] Module ${MODULE_NAME} is not loaded"
    exit 1
fi

BACKUP_DIR="$(mktemp -d)"
BACKUP_FILE="${BACKUP_DIR}/rootwriters.backup"
HAD_CONFIG=0
PASS_COUNT=0
FAIL_COUNT=0

cleanup() {
    set +e
    sudo rm -f "${TEST_FILE}"

    if [ "${HAD_CONFIG}" -eq 1 ]; then
        sudo cp "${BACKUP_FILE}" "${CONFIG_FILE}"
    else
        sudo rm -f "${CONFIG_FILE}"
    fi

    rm -rf "${BACKUP_DIR}"
}
trap cleanup EXIT

run_user_write() {
    local payload="$1"

    if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "${SUDO_USER}" bash -lc "printf '%s\n' '${payload}' > '${TEST_FILE}'"
    else
        bash -lc "printf '%s\n' '${payload}' > '${TEST_FILE}'"
    fi
}

pass() {
    echo "[PASS] $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo "[FAIL] $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "[*] Preparing test environment..."
sudo install -d -m 755 "${CONFIG_DIR}"

if [ -f "${CONFIG_FILE}" ]; then
    sudo cp "${CONFIG_FILE}" "${BACKUP_FILE}"
    HAD_CONFIG=1
fi

sudo rm -f "${TEST_FILE}"
sudo touch "${TEST_FILE}"
sudo chown root:root "${TEST_FILE}"
sudo chmod 666 "${TEST_FILE}"

echo
echo "[1] Missing config file => restrictions do not apply"
sudo rm -f "${CONFIG_FILE}"
sleep 2
if run_user_write "case-1"; then
    pass "write allowed when config file is missing"
else
    fail "write should be allowed when config file is missing"
fi

echo
echo "[2] Empty config file => deny everyone"
sudo : > "${CONFIG_FILE}"
sleep 2
if run_user_write "case-2"; then
    fail "write should be denied when config file is empty"
else
    pass "write denied when config file is empty"
fi

echo
echo "[3] Config with unrelated UID => deny current user"
DUMMY_UID=424242
if [ "${DUMMY_UID}" -eq "${REAL_UID}" ]; then
    DUMMY_UID=424243
fi

sudo tee "${CONFIG_FILE}" >/dev/null <<EOF
# unrelated uid only
${DUMMY_UID} stranger
EOF
sleep 2
if run_user_write "case-3"; then
    fail "write should be denied for non-authorized user"
else
    pass "write denied for non-authorized user"
fi

echo
echo "[4] Config with current UID => allow current user"
sudo tee "${CONFIG_FILE}" >/dev/null <<EOF
# current user is allowed
0 root
${REAL_UID} ${REAL_USER}
EOF
sleep 2
if run_user_write "case-4"; then
    pass "write allowed for authorized uid ${REAL_UID}"
else
    fail "write should be allowed for authorized uid ${REAL_UID}"
fi

echo
echo "[*] Recent kernel log:"
sudo dmesg | tail -n 30 | grep -i "${MODULE_NAME}" || true

echo
echo "[*] Result: PASS=${PASS_COUNT}, FAIL=${FAIL_COUNT}"

if [ "${FAIL_COUNT}" -ne 0 ]; then
    exit 1
fi