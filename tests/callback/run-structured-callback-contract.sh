#!/bin/sh
#
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu

role_root=$(
    CDPATH= cd -- "$(dirname -- "$0")/../.." &&
        pwd
)
harness_root=$(mktemp -d /tmp/docker-ansible-summary-structured.XXXXXX)

cleanup() {
    rm -rf -- "$harness_root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$harness_root/bin" "$harness_root/roles" "$harness_root/run"
chmod 0700 "$harness_root/run"
ln -s "$role_root" "$harness_root/roles/docker_ansible_summary"
install -m 0700 \
    "$role_root/molecule/default/files/docker" \
    "$harness_root/bin/docker"

availability="$harness_root/ansible-posix-json.txt"
if ! (
    export ANSIBLE_LOCAL_TEMP="$harness_root/discovery-local"
    ansible-doc -t callback ansible.posix.json --json
) >"$availability" 2>&1; then
    cat "$availability" >&2
    echo "ansible.posix.json is unavailable in the active collection paths" >&2
    exit 77
fi

stdout_capture="$harness_root/stdout.log"
stderr_capture="$harness_root/stderr.log"
if ! (
    export ANSIBLE_FORCE_COLOR=false
    export ANSIBLE_NOCOLOR=1
    export NO_COLOR=1
    export ANSIBLE_FORKS=1
    export ANSIBLE_LOCAL_TEMP="$harness_root/run/ansible-local"
    export ANSIBLE_REMOTE_TEMP="$harness_root/run/ansible-remote"
    export ANSIBLE_ROLES_PATH="$harness_root/roles"
    export ANSIBLE_STDOUT_CALLBACK=ansible.posix.json
    export ANSIBLE_STRATEGY=linear
    export DAS_STRUCTURED_CALLBACK_BIN="$harness_root/bin"
    export DAS_STRUCTURED_CALLBACK_ROOT="$harness_root/run"
    ansible-playbook \
        --forks 1 \
        --inventory \
        "$role_root/tests/callback/structured-inventory.yml" \
        "$role_root/tests/callback/structured.yml"
) >"$stdout_capture" 2>"$stderr_capture"; then
    cat "$stdout_capture" >&2
    cat "$stderr_capture" >&2
    exit 1
fi

if ! python3 \
    "$role_root/tests/callback/verify_structured_capture.py" \
    --stdout "$stdout_capture" \
    --stderr "$stderr_capture"; then
    cat "$stdout_capture" >&2
    cat "$stderr_capture" >&2
    exit 1
fi
