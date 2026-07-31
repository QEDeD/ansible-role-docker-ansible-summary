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
harness_root=$(mktemp -d /tmp/docker-ansible-summary-callback.XXXXXX)

cleanup() {
    rm -rf -- "$harness_root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$harness_root/bin" "$harness_root/roles"
ln -s "$role_root" "$harness_root/roles/docker_ansible_summary"
install -m 0700 \
    "$role_root/molecule/default/files/docker" \
    "$harness_root/bin/docker"

for result_format in yaml json; do
    for color_mode in off on; do
        capture="$harness_root/callback-$result_format-$color_mode.log"
        run_root="$harness_root/$result_format-$color_mode"
        mkdir -p "$run_root"
        if ! (
            export ANSIBLE_CALLBACK_RESULT_FORMAT="$result_format"
            export ANSIBLE_FORKS=4
            export ANSIBLE_LOCAL_TEMP="$run_root/ansible-local"
            export ANSIBLE_REMOTE_TEMP="$run_root/ansible-remote"
            export ANSIBLE_ROLES_PATH="$harness_root/roles"
            export ANSIBLE_STDOUT_CALLBACK=default
            export ANSIBLE_STRATEGY=linear
            export DAS_CALLBACK_BIN="$harness_root/bin"
            export DAS_CALLBACK_ROOT="$run_root"
            if [ "$color_mode" = off ]; then
                export ANSIBLE_FORCE_COLOR=false
                export ANSIBLE_NOCOLOR=1
                export NO_COLOR=1
            else
                export ANSIBLE_FORCE_COLOR=true
                unset ANSIBLE_NOCOLOR
                unset NO_COLOR
            fi
            ansible-playbook \
                --forks 4 \
                --inventory "$role_root/tests/callback/inventory.yml" \
                "$role_root/tests/callback/multihost.yml"
        ) >"$capture" 2>&1; then
            cat "$capture" >&2
            exit 1
        fi
        if ! python3 "$role_root/tests/callback/verify_capture.py" \
            --capture "$capture" \
            --result-format "$result_format" \
            --color "$color_mode"; then
            cat "$capture" >&2
            exit 1
        fi
    done
done
