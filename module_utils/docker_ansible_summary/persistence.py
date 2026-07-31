# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Secure local-POSIX persistence primitives for DAS v1."""

import contextlib
import copy
import errno
import fcntl
import json
import os
import secrets
import stat
import time

from .validation import (
    COMPARISON_SCHEMA_VERSION,
    SCHEMA_VERSION,
    ValidationError,
    canonical_store_bytes,
    validate_instance_id,
    validate_state_root,
    validate_state_store,
)


LOCK_TIMEOUT_SECONDS = 5
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
STATE_FILENAME = "state.json"
LOCK_FILENAME = "state.lock"


class PersistenceError(RuntimeError):
    """A bounded persistence failure without raw OS or parser text."""

    def __init__(
        self,
        reason,
        persistence_outcome="failed",
        replacement_completed=False,
        replay_guidance=None,
    ):
        RuntimeError.__init__(self, reason)
        self.reason = reason
        self.persistence_outcome = persistence_outcome
        self.replacement_completed = replacement_completed
        self.replay_guidance = replay_guidance


class _DuplicateKey(ValueError):
    pass


def _empty_store(instance_id):
    return {
        "schema_version": SCHEMA_VERSION,
        "comparison_schema_version": COMPARISON_SCHEMA_VERSION,
        "instance_id": instance_id,
        "revision": 0,
        "latest_complete_post": None,
        "journal": [],
        "recently_pruned_record_ids": [],
    }


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ValueError()


def decode_store_bytes(
    source,
    expected_instance_id,
    state_max_bytes,
    release_validation=True,
):
    """Decode only exact canonical v1 store bytes."""

    if not isinstance(source, bytes):
        raise PersistenceError("corrupt_state")
    if len(source) > state_max_bytes:
        raise PersistenceError("state_size_limit_exceeded")
    try:
        text = source.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        validate_state_store(
            value,
            expected_instance_id=expected_instance_id,
            release=release_validation,
        )
        expected = canonical_store_bytes(
            value,
            expected_instance_id=expected_instance_id,
            release=release_validation,
        )
    except (
        UnicodeError,
        ValueError,
        TypeError,
        ValidationError,
        _DuplicateKey,
        RecursionError,
    ):
        raise PersistenceError("corrupt_state")
    if source != expected:
        raise PersistenceError("corrupt_state")
    return value


class PosixStateStore(object):
    """Descriptor-relative implementation of the frozen filesystem contract.

    Dependencies are constructor-injected so tests can control clocks, lock
    calls, random names, and fault boundaries without changing production code.
    """

    def __init__(
        self,
        state_root,
        instance_id,
        os_module=None,
        fcntl_module=None,
        monotonic=None,
        sleeper=None,
        token_factory=None,
        effective_uid=None,
        trusted_root_uid=0,
        fault_injector=None,
        lock_timeout_seconds=LOCK_TIMEOUT_SECONDS,
        release_validation=True,
    ):
        self.state_root = validate_state_root(state_root)
        self.instance_id = validate_instance_id(instance_id)
        self.os = os_module or os
        self.fcntl = fcntl_module or fcntl
        self.monotonic = monotonic or time.monotonic
        self.sleeper = sleeper or time.sleep
        self.token_factory = token_factory or (lambda: secrets.token_hex(16))
        self.effective_uid = (
            self.os.geteuid() if effective_uid is None else effective_uid
        )
        self.trusted_root_uid = trusted_root_uid
        self.fault_injector = fault_injector
        self.lock_timeout_seconds = lock_timeout_seconds
        self.release_validation = release_validation
        if lock_timeout_seconds != LOCK_TIMEOUT_SECONDS:
            # This constructor seam exists for deterministic tests, not as a
            # public role setting.  Positive sub-five values are useful in
            # isolated tests; production always supplies the frozen constant.
            if lock_timeout_seconds <= 0 or lock_timeout_seconds > LOCK_TIMEOUT_SECONDS:
                raise ValueError("invalid lock timeout")

    def _directory_flags(self):
        required = ("O_DIRECTORY", "O_NOFOLLOW")
        if any(not hasattr(self.os, name) for name in required):
            raise PersistenceError("unsafe_state_namespace")
        return (
            self.os.O_RDONLY
            | self.os.O_DIRECTORY
            | self.os.O_NOFOLLOW
            | getattr(self.os, "O_CLOEXEC", 0)
        )

    def _file_flags(self, access):
        if not hasattr(self.os, "O_NOFOLLOW"):
            raise PersistenceError("unsafe_state_namespace")
        return (
            access
            | self.os.O_NOFOLLOW
            | getattr(self.os, "O_CLOEXEC", 0)
            | getattr(self.os, "O_NONBLOCK", 0)
        )

    def _same_identity(self, first, second):
        return first.st_dev == second.st_dev and first.st_ino == second.st_ino

    def _stat_name(self, directory_fd, name):
        try:
            return self.os.stat(
                name, dir_fd=directory_fd, follow_symlinks=False
            )
        except (OSError, TypeError):
            raise PersistenceError("unsafe_state_namespace")

    def _validate_directory_descriptor(
        self, descriptor, parent_fd=None, name=None, role_owned=False
    ):
        try:
            descriptor_stat = self.os.fstat(descriptor)
        except OSError:
            raise PersistenceError("unsafe_state_namespace")
        if not stat.S_ISDIR(descriptor_stat.st_mode):
            raise PersistenceError("unsafe_state_namespace")
        if parent_fd is not None:
            name_stat = self._stat_name(parent_fd, name)
            if (
                stat.S_ISLNK(name_stat.st_mode)
                or not self._same_identity(descriptor_stat, name_stat)
            ):
                raise PersistenceError("unsafe_state_namespace")

        mode = stat.S_IMODE(descriptor_stat.st_mode)
        if role_owned:
            if descriptor_stat.st_uid != self.effective_uid or mode != DIRECTORY_MODE:
                raise PersistenceError("unsafe_state_namespace")
        else:
            if descriptor_stat.st_uid not in (
                self.trusted_root_uid,
                self.effective_uid,
            ):
                raise PersistenceError("unsafe_state_namespace")
            writable = bool(mode & 0o022)
            root_sticky = (
                descriptor_stat.st_uid == self.trusted_root_uid
                and bool(descriptor_stat.st_mode & stat.S_ISVTX)
            )
            if writable and not root_sticky:
                raise PersistenceError("unsafe_state_namespace")
        return descriptor_stat

    def _open_directory(self, parent_fd, name, role_owned):
        try:
            descriptor = self.os.open(
                name, self._directory_flags(), dir_fd=parent_fd
            )
        except OSError:
            raise PersistenceError("unsafe_state_namespace")
        try:
            self._validate_directory_descriptor(
                descriptor,
                parent_fd=parent_fd,
                name=name,
                role_owned=role_owned,
            )
        except Exception:
            self.os.close(descriptor)
            raise
        return descriptor

    def _mkdir_and_open(self, parent_fd, name):
        created = False
        try:
            self.os.mkdir(name, DIRECTORY_MODE, dir_fd=parent_fd)
            created = True
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise PersistenceError("unsafe_state_namespace")
        if created:
            try:
                descriptor = self.os.open(
                    name, self._directory_flags(), dir_fd=parent_fd
                )
            except OSError:
                raise PersistenceError("unsafe_state_namespace")
            try:
                self.os.fchmod(descriptor, DIRECTORY_MODE)
                self._validate_directory_descriptor(
                    descriptor,
                    parent_fd=parent_fd,
                    name=name,
                    role_owned=True,
                )
            except Exception:
                self.os.close(descriptor)
                raise
        else:
            descriptor = self._open_directory(
                parent_fd, name, role_owned=True
            )
        if created:
            try:
                self.os.fsync(parent_fd)
            except OSError:
                self.os.close(descriptor)
                raise PersistenceError("state_write_failed")
        return descriptor

    def _open_namespace(self, create):
        root_fd = None
        current_fd = None
        try:
            root_fd = self.os.open("/", self._directory_flags())
            self._validate_directory_descriptor(root_fd, role_owned=False)
            current_fd = root_fd
            components = self.state_root.split("/")[1:]
            for index, component in enumerate(components):
                is_state_root = index == len(components) - 1
                try:
                    child_fd = self.os.open(
                        component, self._directory_flags(), dir_fd=current_fd
                    )
                except OSError as error:
                    if error.errno == errno.ENOENT and is_state_root:
                        if not create:
                            return None
                        child_fd = self._mkdir_and_open(current_fd, component)
                    else:
                        raise PersistenceError("unsafe_state_namespace")
                try:
                    self._validate_directory_descriptor(
                        child_fd,
                        parent_fd=current_fd,
                        name=component,
                        role_owned=is_state_root,
                    )
                except Exception:
                    self.os.close(child_fd)
                    raise
                if current_fd != root_fd:
                    self.os.close(current_fd)
                current_fd = child_fd

            state_root_fd = current_fd
            current_fd = None
            try:
                try:
                    instance_fd = self.os.open(
                        self.instance_id,
                        self._directory_flags(),
                        dir_fd=state_root_fd,
                    )
                except OSError as error:
                    if error.errno == errno.ENOENT:
                        if not create:
                            return None
                        instance_fd = self._mkdir_and_open(
                            state_root_fd, self.instance_id
                        )
                    else:
                        raise PersistenceError("unsafe_state_namespace")
                try:
                    self._validate_directory_descriptor(
                        instance_fd,
                        parent_fd=state_root_fd,
                        name=self.instance_id,
                        role_owned=True,
                    )
                except Exception:
                    self.os.close(instance_fd)
                    raise
                return instance_fd
            finally:
                self.os.close(state_root_fd)
        finally:
            if current_fd is not None and current_fd != root_fd:
                self.os.close(current_fd)
            if root_fd is not None:
                self.os.close(root_fd)

    def _validate_regular_descriptor(self, directory_fd, name, descriptor):
        try:
            descriptor_stat = self.os.fstat(descriptor)
            name_stat = self._stat_name(directory_fd, name)
        except OSError:
            raise PersistenceError("unsafe_state_namespace")
        if (
            not stat.S_ISREG(descriptor_stat.st_mode)
            or stat.S_ISLNK(name_stat.st_mode)
            or not self._same_identity(descriptor_stat, name_stat)
            or descriptor_stat.st_uid != self.effective_uid
            or stat.S_IMODE(descriptor_stat.st_mode) != FILE_MODE
            or descriptor_stat.st_nlink != 1
        ):
            raise PersistenceError("unsafe_state_namespace")
        return descriptor_stat

    def _open_existing_regular(self, directory_fd, name, access):
        try:
            descriptor = self.os.open(
                name, self._file_flags(access), dir_fd=directory_fd
            )
        except OSError as error:
            if error.errno == errno.ENOENT:
                return None
            raise PersistenceError("unsafe_state_namespace")
        try:
            self._validate_regular_descriptor(directory_fd, name, descriptor)
        except Exception:
            self.os.close(descriptor)
            raise
        return descriptor

    def _open_or_create_lock(self, directory_fd, create=True):
        created = False
        if not create:
            descriptor = self._open_existing_regular(
                directory_fd, LOCK_FILENAME, self.os.O_RDWR
            )
            if descriptor is None:
                raise PersistenceError("unsafe_state_namespace")
            return descriptor
        flags = self._file_flags(self.os.O_RDWR) | self.os.O_CREAT | self.os.O_EXCL
        try:
            descriptor = self.os.open(
                LOCK_FILENAME, flags, FILE_MODE, dir_fd=directory_fd
            )
            created = True
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise PersistenceError("unsafe_state_namespace")
            descriptor = self._open_existing_regular(
                directory_fd, LOCK_FILENAME, self.os.O_RDWR
            )
            if descriptor is None:
                raise PersistenceError("unsafe_state_namespace")
        try:
            if created:
                self.os.fchmod(descriptor, FILE_MODE)
            self._validate_regular_descriptor(
                directory_fd, LOCK_FILENAME, descriptor
            )
            if created:
                self.os.fsync(directory_fd)
        except OSError:
            self.os.close(descriptor)
            raise PersistenceError("state_write_failed")
        except Exception:
            self.os.close(descriptor)
            raise
        return descriptor

    def _acquire_lock(self, lock_fd):
        started = self.monotonic()
        deadline = started + self.lock_timeout_seconds
        first_attempt = True
        while True:
            if not first_attempt and self.monotonic() >= deadline:
                raise PersistenceError("state_lock_timeout")
            first_attempt = False
            try:
                self.fcntl.flock(
                    lock_fd, self.fcntl.LOCK_EX | self.fcntl.LOCK_NB
                )
                return
            except (IOError, OSError) as error:
                if getattr(error, "errno", None) not in (
                    errno.EACCES,
                    errno.EAGAIN,
                ):
                    raise PersistenceError("unsafe_state_namespace")
            now = self.monotonic()
            if now >= deadline:
                raise PersistenceError("state_lock_timeout")
            self.sleeper(min(0.05, deadline - now))

    @contextlib.contextmanager
    def _locked_namespace(self, create_namespace, create_lock=True):
        instance_fd = self._open_namespace(create_namespace)
        if instance_fd is None:
            yield None
            return
        lock_fd = None
        try:
            lock_fd = self._open_or_create_lock(
                instance_fd, create=create_lock
            )
            self._acquire_lock(lock_fd)
            self._validate_regular_descriptor(
                instance_fd, LOCK_FILENAME, lock_fd
            )
            yield instance_fd
        finally:
            if lock_fd is not None:
                try:
                    self.fcntl.flock(lock_fd, self.fcntl.LOCK_UN)
                finally:
                    self.os.close(lock_fd)
            self.os.close(instance_fd)

    def _name_exists(self, instance_fd, name):
        try:
            self.os.stat(
                name,
                dir_fd=instance_fd,
                follow_symlinks=False,
            )
            return True
        except OSError as error:
            if error.errno == errno.ENOENT:
                return False
            raise PersistenceError("unsafe_state_namespace")

    def _read_state_locked(self, instance_fd, state_max_bytes):
        state_fd = self._open_existing_regular(
            instance_fd, STATE_FILENAME, self.os.O_RDONLY
        )
        if state_fd is None:
            return _empty_store(self.instance_id)
        try:
            metadata = self.os.fstat(state_fd)
            if metadata.st_size > state_max_bytes:
                raise PersistenceError("state_size_limit_exceeded")
            chunks = []
            remaining = metadata.st_size
            while remaining:
                chunk = self.os.read(state_fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if remaining:
                raise PersistenceError("corrupt_state")
            self._validate_regular_descriptor(
                instance_fd, STATE_FILENAME, state_fd
            )
            return decode_store_bytes(
                b"".join(chunks),
                self.instance_id,
                state_max_bytes,
                release_validation=self.release_validation,
            )
        finally:
            self.os.close(state_fd)

    def load(self, state_max_bytes, create_namespace=False):
        """Load a locked authoritative snapshot, or an empty revision-0 store."""

        # A supplied-post probe of a wholly absent namespace must not create
        # even the stable lock.  Existing canonical state always uses the lock.
        if not create_namespace:
            instance_fd = self._open_namespace(False)
            if instance_fd is None:
                return _empty_store(self.instance_id)
            try:
                state_exists = self._name_exists(
                    instance_fd, STATE_FILENAME
                )
                lock_exists = self._name_exists(
                    instance_fd, LOCK_FILENAME
                )
                if not state_exists and not lock_exists:
                    return _empty_store(self.instance_id)
                if state_exists:
                    probe_fd = self._open_existing_regular(
                        instance_fd, STATE_FILENAME, self.os.O_RDONLY
                    )
                    if probe_fd is None:
                        raise PersistenceError("unsafe_state_namespace")
                    self.os.close(probe_fd)
            finally:
                self.os.close(instance_fd)
        else:
            state_exists = False
            lock_exists = False

        with self._locked_namespace(
            create_namespace,
            create_lock=(
                create_namespace or state_exists or not lock_exists
            ),
        ) as instance_fd:
            if instance_fd is None:
                return _empty_store(self.instance_id)
            return self._read_state_locked(instance_fd, state_max_bytes)

    def _inject_fault(self, stage):
        if self.fault_injector is not None:
            self.fault_injector(stage)

    def _temporary_name(self):
        token = self.token_factory()
        if not isinstance(token, str) or not token:
            raise PersistenceError("state_write_failed")
        safe = all(character in "0123456789abcdef" for character in token)
        if not safe or len(token) > 128:
            raise PersistenceError("state_write_failed")
        return ".state.json.tmp." + token

    def _unlink_own_temporary(self, directory_fd, name, descriptor_stat):
        try:
            name_stat = self.os.stat(
                name, dir_fd=directory_fd, follow_symlinks=False
            )
            if self._same_identity(name_stat, descriptor_stat):
                self.os.unlink(name, dir_fd=directory_fd)
        except OSError:
            return

    def _atomic_replace_locked(self, instance_fd, encoded):
        temporary_name = self._temporary_name()
        temporary_fd = None
        temporary_stat = None
        replaced = False
        try:
            flags = (
                self._file_flags(self.os.O_WRONLY)
                | self.os.O_CREAT
                | self.os.O_EXCL
            )
            temporary_fd = self.os.open(
                temporary_name,
                flags,
                FILE_MODE,
                dir_fd=instance_fd,
            )
            self.os.fchmod(temporary_fd, FILE_MODE)
            temporary_stat = self._validate_regular_descriptor(
                instance_fd, temporary_name, temporary_fd
            )

            offset = 0
            while offset < len(encoded):
                written = self.os.write(temporary_fd, encoded[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                offset += written
            self.os.fsync(temporary_fd)
            self._validate_regular_descriptor(
                instance_fd, temporary_name, temporary_fd
            )
            self._inject_fault("before_atomic_replace")
            self.os.rename(
                temporary_name,
                STATE_FILENAME,
                src_dir_fd=instance_fd,
                dst_dir_fd=instance_fd,
            )
            replaced = True
            self._inject_fault("after_atomic_replace_before_directory_fsync")
            self.os.fsync(instance_fd)
        except PersistenceError:
            raise
        except Exception:
            guidance = None
            if replaced:
                guidance = (
                    "Retry with the same record_id and unchanged phase inputs"
                )
            raise PersistenceError(
                "state_write_failed",
                replacement_completed=replaced,
                replay_guidance=guidance,
            )
        finally:
            if temporary_fd is not None:
                self.os.close(temporary_fd)
            if not replaced and temporary_stat is not None:
                self._unlink_own_temporary(
                    instance_fd, temporary_name, temporary_stat
                )

    def commit(
        self,
        candidate,
        expected_revision,
        state_max_bytes,
        conflict_resolver=None,
    ):
        """Commit one validated candidate under the stable lock.

        A conflict resolver, when supplied, runs under the lock with a deep
        copy of the current state.  It can implement same-phase replay
        precedence without a racy second load.
        """

        with self._locked_namespace(True) as instance_fd:
            current = self._read_state_locked(instance_fd, state_max_bytes)
            if current["revision"] != expected_revision:
                if conflict_resolver is not None:
                    return conflict_resolver(copy.deepcopy(current))
                raise PersistenceError(
                    "revision_conflict", persistence_outcome="conflict"
                )
            try:
                validate_state_store(
                    candidate,
                    expected_instance_id=self.instance_id,
                    release=self.release_validation,
                )
                if candidate["revision"] != expected_revision + 1:
                    raise ValidationError("invalid_candidate_revision")
                encoded = canonical_store_bytes(
                    candidate,
                    expected_instance_id=self.instance_id,
                    release=self.release_validation,
                )
            except ValidationError:
                raise PersistenceError("state_write_failed")
            if len(encoded) > state_max_bytes:
                raise PersistenceError("state_size_limit_exceeded")
            self._atomic_replace_locked(instance_fd, encoded)
            return copy.deepcopy(candidate)

    def transact(self, expected_revision, state_max_bytes, builder):
        """Build and commit under one lock, or return a builder no-write result.

        ``builder(current)`` may return a StateStore candidate directly or
        ``(candidate, result)``.  A ``None`` candidate performs no write and
        returns the result, supporting atomic replay/conflict resolution.
        """

        with self._locked_namespace(True) as instance_fd:
            current = self._read_state_locked(instance_fd, state_max_bytes)
            built = builder(copy.deepcopy(current))
            result = None
            if isinstance(built, tuple):
                candidate, result = built
            else:
                candidate = built
            if candidate is None:
                return result
            if current["revision"] != expected_revision:
                raise PersistenceError(
                    "revision_conflict", persistence_outcome="conflict"
                )
            try:
                validate_state_store(
                    candidate,
                    expected_instance_id=self.instance_id,
                    release=self.release_validation,
                )
                if candidate["revision"] != expected_revision + 1:
                    raise ValidationError("invalid_candidate_revision")
                encoded = canonical_store_bytes(
                    candidate,
                    expected_instance_id=self.instance_id,
                    release=self.release_validation,
                )
            except ValidationError:
                raise PersistenceError("state_write_failed")
            if len(encoded) > state_max_bytes:
                raise PersistenceError("state_size_limit_exceeded")
            self._atomic_replace_locked(instance_fd, encoded)
            return result if result is not None else copy.deepcopy(candidate)


def load_store(
    state_root,
    instance_id,
    state_max_bytes,
    create_namespace=False,
    backend=None,
    **backend_dependencies
):
    """Functional wrapper around :meth:`PosixStateStore.load`."""

    store = backend or PosixStateStore(
        state_root, instance_id, **backend_dependencies
    )
    return store.load(
        state_max_bytes=state_max_bytes,
        create_namespace=create_namespace,
    )


def commit_store(
    state_root,
    instance_id,
    candidate,
    expected_revision,
    state_max_bytes,
    conflict_resolver=None,
    backend=None,
    **backend_dependencies
):
    """Functional wrapper around :meth:`PosixStateStore.commit`."""

    store = backend or PosixStateStore(
        state_root, instance_id, **backend_dependencies
    )
    return store.commit(
        candidate,
        expected_revision=expected_revision,
        state_max_bytes=state_max_bytes,
        conflict_resolver=conflict_resolver,
    )
