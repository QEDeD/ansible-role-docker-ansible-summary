#!/bin/sh
#
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu
export PYTHONDONTWRITEBYTECODE=1

role_root=$(
    CDPATH= cd -- "$(dirname -- "$0")/../.." &&
        pwd
)
harness_root=$(mktemp -d /tmp/docker-ansible-summary-callback-failure.XXXXXX)
lock_holder_pid=

stop_lock_holder() {
    if [ -n "$lock_holder_pid" ]; then
        kill "$lock_holder_pid" 2>/dev/null || true
        wait "$lock_holder_pid" 2>/dev/null || true
        lock_holder_pid=
    fi
}

cleanup() {
    stop_lock_holder
    rm -rf -- "$harness_root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p \
    "$harness_root/bin" \
    "$harness_root/roles" \
    "$harness_root/injected-roles/docker_ansible_summary/action_plugins" \
    "$harness_root/injected-roles/docker_ansible_summary/library"
ln -s "$role_root" "$harness_root/roles/docker_ansible_summary"
injected_role="$harness_root/injected-roles/docker_ansible_summary"
ln -s "$role_root/defaults" "$injected_role/defaults"
ln -s "$role_root/meta" "$injected_role/meta"
ln -s "$role_root/module_utils" "$injected_role/module_utils"
ln -s "$role_root/tasks" "$injected_role/tasks"
install -m 0600 \
    "$role_root/tests/callback/failure-injected-action.py" \
    "$injected_role/action_plugins/docker_ansible_summary.py"
install -m 0700 \
    "$role_root/tests/callback/failure-injected-module.py" \
    "$injected_role/library/docker_ansible_summary.py"
install -m 0700 \
    "$role_root/tests/callback/failure-docker.py" \
    "$harness_root/bin/docker"

prepare_persistence_case() {
    persistence_case=$1
    persistence_root=$2
    persistence_state_dir=$persistence_case
    persistence_state_root="$persistence_root/$persistence_state_dir"
    persistence_instance="$persistence_state_root/callback-persistence"

    case "$persistence_case" in
        unsafe-state)
            install -m 0600 /dev/null "$persistence_state_root"
            ;;
        corrupt-state)
            mkdir -p "$persistence_instance"
            chmod 0700 "$persistence_state_root" "$persistence_instance"
            install -m 0600 /dev/null \
                "$persistence_instance/state.json"
            ;;
        state-size)
            mkdir -p "$persistence_instance"
            chmod 0700 "$persistence_state_root" "$persistence_instance"
            dd \
                if=/dev/zero \
                of="$persistence_instance/state.json" \
                bs=1 \
                count=0 \
                seek=1048577 \
                2>/dev/null
            chmod 0600 "$persistence_instance/state.json"
            ;;
        lock-timeout)
            mkdir -p "$persistence_instance"
            chmod 0700 "$persistence_state_root" "$persistence_instance"
            install -m 0600 /dev/null \
                "$persistence_instance/state.lock"
            lock_ready="$persistence_root/lock-holder.ready"
            python3 \
                "$role_root/tests/callback/failure-lock-holder.py" \
                --lock "$persistence_instance/state.lock" \
                --ready "$lock_ready" &
            lock_holder_pid=$!
            lock_wait_count=0
            while [ ! -f "$lock_ready" ]; do
                if ! kill -0 "$lock_holder_pid" 2>/dev/null; then
                    wait "$lock_holder_pid" || true
                    lock_holder_pid=
                    echo "lock holder exited before readiness" >&2
                    exit 1
                fi
                lock_wait_count=$((lock_wait_count + 1))
                if [ "$lock_wait_count" -ge 100 ]; then
                    echo "lock holder did not become ready" >&2
                    exit 1
                fi
                sleep 0.05
            done
            ;;
        *)
            echo "unknown persistence callback case: $persistence_case" >&2
            exit 1
            ;;
    esac
    export DAS_CALLBACK_FAILURE_STATE_DIR="$persistence_state_dir"
    export DAS_CALLBACK_FAILURE_RECORD_ID="callback-$persistence_case-record"
}

prepare_capacity_state() {
    capacity_root=$1
    capacity_log=$2
    if ! (
        export ANSIBLE_CALLBACK_RESULT_FORMAT=yaml
        export ANSIBLE_DISPLAY_OK_HOSTS=false
        export ANSIBLE_FORCE_COLOR=false
        export ANSIBLE_NOCOLOR=1
        export NO_COLOR=1
        export ANSIBLE_FORKS=1
        export ANSIBLE_LOCAL_TEMP="$capacity_root/prepare-ansible-local"
        export ANSIBLE_REMOTE_TEMP="$capacity_root/prepare-ansible-remote"
        export ANSIBLE_ROLES_PATH="$harness_root/roles"
        export ANSIBLE_STDOUT_CALLBACK=default
        export ANSIBLE_STRATEGY=linear
        export DAS_CALLBACK_FAILURE_BIN="$harness_root/bin"
        export DAS_CALLBACK_FAILURE_ROOT="$capacity_root"
        ansible-playbook \
            --forks 1 \
            --inventory \
            "$role_root/tests/callback/failure-inventory.yml" \
            "$role_root/tests/callback/failure-capacity-prepare.yml"
    ) >"$capacity_log" 2>&1; then
        cat "$capacity_log" >&2
        echo "capacity pre-observation preparation failed" >&2
        exit 1
    fi
}

prepare_injected_state() {
    injected_case=$1
    injected_root=$2
    injected_log="$injected_root/injected-prepare.log"
    case "$injected_case" in
        state-write-before|state-write-after)
            injected_playbook=\
"$role_root/tests/callback/failure-injection-seed.yml"
            injected_state_path=\
"$injected_root/injected-state/callback-injection/state.json"
            ;;
        render-failed)
            injected_playbook=\
"$role_root/tests/callback/failure-render-prepare.yml"
            injected_state_path=\
"$injected_root/render-state/callback-render/state.json"
            ;;
        *)
            echo "unknown injected callback case: $injected_case" >&2
            exit 1
            ;;
    esac
    if ! (
        export ANSIBLE_CALLBACK_RESULT_FORMAT=yaml
        export ANSIBLE_DISPLAY_OK_HOSTS=false
        export ANSIBLE_FORCE_COLOR=false
        export ANSIBLE_NOCOLOR=1
        export NO_COLOR=1
        export ANSIBLE_FORKS=1
        export ANSIBLE_LOCAL_TEMP="$injected_root/prepare-ansible-local"
        export ANSIBLE_REMOTE_TEMP="$injected_root/prepare-ansible-remote"
        export ANSIBLE_ROLES_PATH="$harness_root/injected-roles"
        export ANSIBLE_STDOUT_CALLBACK=default
        export ANSIBLE_STRATEGY=linear
        export DAS_CALLBACK_FAILURE_BIN="$harness_root/bin"
        export DAS_CALLBACK_FAILURE_INJECTION=none
        export DAS_CALLBACK_FAILURE_PRODUCTION_ROLE_ROOT="$role_root"
        export DAS_CALLBACK_FAILURE_ROOT="$injected_root"
        ansible-playbook \
            --forks 1 \
            --inventory \
            "$role_root/tests/callback/failure-inventory.yml" \
            "$injected_playbook"
    ) >"$injected_log" 2>&1; then
        cat "$injected_log" >&2
        echo "injected callback state preparation failed" >&2
        exit 1
    fi
    cp "$injected_state_path" "$injected_root/state-before.json"
}

run_expected_failure() {
    run_case=$1
    run_playbook=$2
    run_format=$3
    run_color=$4
    run_root=$5
    run_capture=$6
    run_status=0
    run_roles_path="$harness_root/roles"
    run_injection=none
    run_state_path=
    run_state_record=

    if [ "$run_case" = capacity ]; then
        prepare_capacity_state "$run_root" "$run_root/capacity-prepare.log"
    fi
    case "$run_case" in
        unsafe-state|corrupt-state|state-size|lock-timeout)
            prepare_persistence_case "$run_case" "$run_root"
            ;;
    esac
    case "$run_case" in
        state-write-before)
            prepare_injected_state "$run_case" "$run_root"
            run_roles_path="$harness_root/injected-roles"
            run_injection=before_atomic_replace
            run_state_path=\
"$run_root/injected-state/callback-injection/state.json"
            run_state_record=callback-write-before-record
            export DAS_CALLBACK_FAILURE_RECORD_ID="$run_state_record"
            ;;
        state-write-after)
            prepare_injected_state "$run_case" "$run_root"
            run_roles_path="$harness_root/injected-roles"
            run_injection=after_atomic_replace_before_directory_fsync
            run_state_path=\
"$run_root/injected-state/callback-injection/state.json"
            run_state_record=callback-write-after-record
            export DAS_CALLBACK_FAILURE_RECORD_ID="$run_state_record"
            ;;
        render-failed)
            prepare_injected_state "$run_case" "$run_root"
            run_roles_path="$harness_root/injected-roles"
            run_injection=render_failed
            run_state_path="$run_root/render-state/callback-render/state.json"
            run_state_record=callback-render-record
            ;;
    esac

    (
        export ANSIBLE_CALLBACK_RESULT_FORMAT="$run_format"
        export ANSIBLE_DISPLAY_OK_HOSTS=false
        export ANSIBLE_FORKS=2
        export ANSIBLE_LOCAL_TEMP="$run_root/ansible-local"
        export ANSIBLE_REMOTE_TEMP="$run_root/ansible-remote"
        export ANSIBLE_ROLES_PATH="$run_roles_path"
        export ANSIBLE_STDOUT_CALLBACK=default
        export ANSIBLE_STRATEGY=linear
        export DAS_CALLBACK_FAILURE_BIN="$harness_root/bin"
        export DAS_CALLBACK_FAILURE_INJECTION="$run_injection"
        export DAS_CALLBACK_FAILURE_PRODUCTION_ROLE_ROOT="$role_root"
        export DAS_CALLBACK_FAILURE_ROOT="$run_root"
        if [ "$run_color" = off ]; then
            export ANSIBLE_FORCE_COLOR=false
            export ANSIBLE_NOCOLOR=1
            export NO_COLOR=1
        else
            export ANSIBLE_FORCE_COLOR=true
            unset ANSIBLE_NOCOLOR
            unset NO_COLOR
        fi
        ansible-playbook \
            --forks 2 \
            --inventory \
            "$role_root/tests/callback/failure-inventory.yml" \
            "$run_playbook"
    ) >"$run_capture" 2>&1 || run_status=$?

    stop_lock_holder
    unset DAS_CALLBACK_FAILURE_STATE_DIR
    unset DAS_CALLBACK_FAILURE_RECORD_ID

    if [ "$run_status" -eq 0 ]; then
        cat "$run_capture" >&2
        echo "expected callback failure playbook to exit nonzero" >&2
        exit 1
    fi
    if ! python3 \
        "$role_root/tests/callback/verify_failure_capture.py" \
        --capture "$run_capture" \
        --result-format "$run_format" \
        --color "$run_color" \
        --case "$run_case"; then
        cat "$run_capture" >&2
        exit 1
    fi
    if [ -n "$run_state_path" ]; then
        cp "$run_state_path" "$run_root/state-after.json"
        if ! python3 \
            "$role_root/tests/callback/failure-verify-state.py" \
            --case "$run_case" \
            --before "$run_root/state-before.json" \
            --after "$run_root/state-after.json" \
            --record-id "$run_state_record"; then
            exit 1
        fi
    fi
}

for result_format in yaml json; do
    for color_mode in off on; do
        for case_name in \
            unavailable \
            validation \
            unsafe-state \
            corrupt-state \
            state-size \
            lock-timeout \
            state-write-before \
            state-write-after \
            render-failed \
            conflict \
            capacity; do
            lane_root="$harness_root/$result_format-$color_mode-$case_name"
            capture="$lane_root/failure.log"
            mkdir -p "$lane_root"
            chmod 0700 "$lane_root"
            case "$case_name" in
                unavailable)
                    playbook="$role_root/tests/callback/failure.yml"
                    ;;
                validation)
                    playbook="$role_root/tests/callback/failure-validation.yml"
                    ;;
                unsafe-state|corrupt-state|state-size|lock-timeout)
                    playbook="$role_root/tests/callback/failure-persistence.yml"
                    ;;
                state-write-before|state-write-after)
                    playbook=\
"$role_root/tests/callback/failure-injected-persistence.yml"
                    ;;
                render-failed)
                    playbook="$role_root/tests/callback/failure-render.yml"
                    ;;
                conflict)
                    playbook="$role_root/tests/callback/failure-conflict.yml"
                    ;;
                capacity)
                    playbook="$role_root/tests/callback/failure-capacity.yml"
                    ;;
            esac
            run_expected_failure \
                "$case_name" \
                "$playbook" \
                "$result_format" \
                "$color_mode" \
                "$lane_root" \
                "$capture"
        done
    done
done
