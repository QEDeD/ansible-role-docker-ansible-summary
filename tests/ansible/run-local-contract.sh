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
harness_root=$(mktemp -d /tmp/docker-ansible-summary-contract.XXXXXX)

cleanup() {
    rm -rf -- "$harness_root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$harness_root/bin" "$harness_root/roles"
ln -s "$role_root" "$harness_root/roles/docker_ansible_summary"
install -m 0700 \
    "$role_root/molecule/default/files/docker" \
    "$harness_root/bin/docker"

ANSIBLE_LOCAL_TEMP="$harness_root/ansible-local" \
ANSIBLE_REMOTE_TEMP="$harness_root/ansible-remote" \
ANSIBLE_ROLES_PATH="$harness_root/roles" \
DAS_TEST_BIN="$harness_root/bin" \
DAS_TEST_DOCKER_LOG="$harness_root/docker-calls.jsonl" \
DAS_TEST_STATE_ROOT="$harness_root/state" \
ansible-playbook \
    --inventory localhost, \
    "$role_root/tests/ansible/local_contract.yml"
