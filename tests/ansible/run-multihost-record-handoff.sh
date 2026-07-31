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
harness_root=$(mktemp -d /tmp/docker-ansible-summary-handoff.XXXXXX)
capture="$harness_root/ansible.log"
spy_log="$harness_root/logs/action-spy.jsonl"

cleanup() {
    rm -rf -- "$harness_root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p \
    "$harness_root/bin" \
    "$harness_root/logs" \
    "$harness_root/roles/docker_ansible_summary/action_plugins"
for role_directory in defaults library meta module_utils tasks; do
    ln -s \
        "$role_root/$role_directory" \
        "$harness_root/roles/docker_ansible_summary/$role_directory"
done
install -m 0600 /dev/null "$spy_log"
install -m 0600 \
    "$role_root/tests/ansible/action-spy/docker_ansible_summary.py" \
    "$harness_root/roles/docker_ansible_summary/action_plugins/docker_ansible_summary.py"
install -m 0700 \
    "$role_root/molecule/default/files/docker" \
    "$harness_root/bin/docker"

if ! (
    export ANSIBLE_CALLBACK_RESULT_FORMAT=yaml
    export ANSIBLE_FORCE_COLOR=false
    export ANSIBLE_FORKS=4
    export ANSIBLE_HOME="$harness_root/ansible-home"
    export ANSIBLE_LOCAL_TEMP="$harness_root/ansible-local"
    export ANSIBLE_NOCOLOR=1
    export ANSIBLE_REMOTE_TEMP="$harness_root/ansible-remote"
    export ANSIBLE_ROLES_PATH="$harness_root/roles"
    export ANSIBLE_STDOUT_CALLBACK=default
    export ANSIBLE_STRATEGY=linear
    export DAS_HANDOFF_BIN="$harness_root/bin"
    export DAS_HANDOFF_ROOT="$harness_root"
    export DAS_ACTION_SPY_LOG="$spy_log"
    export DAS_ACTION_SPY_REAL_PLUGIN="$role_root/action_plugins/docker_ansible_summary.py"
    export NO_COLOR=1
    ansible-playbook \
        --forks 4 \
        --inventory \
        "$role_root/tests/ansible/multihost-record-handoff-inventory.yml" \
        "$role_root/tests/ansible/multihost-record-handoff.yml"
) >"$capture" 2>&1; then
    cat "$capture" >&2
    exit 1
fi

if ! python3 \
    "$role_root/tests/ansible/verify-multihost-record-handoff.py" \
    --capture "$capture" \
    --docker-log-root "$harness_root/logs" \
    --spy-log "$spy_log"; then
    cat "$capture" >&2
    exit 1
fi
