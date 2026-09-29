import pytest

from ecomops.core.exceptions import ReadOnlyViolation
from ecomops.ssh.read_only import ReadOnlyPolicy, validate_read_only_command


@pytest.mark.parametrize(
    "path",
    [
        "/var/log/app.log",
        "var/log/app.log",
        "../logs/app.log",
        "../logs/example-shop/transfer.log",
        "/var/log/store front/app's error.log",
    ],
)
def test_log_paths_are_accepted(path: str) -> None:
    assert ReadOnlyPolicy.validate_path(path) == path


def test_tail_bytes_command_is_fixed_bounded_and_safely_quotes_the_path() -> None:
    command = ReadOnlyPolicy.build_tail_bytes_command(
        "/var/log/store front/app's error.log", 100
    )

    assert command == ("tail -c 100 -- '/var/log/store front/app'\"'\"'s error.log'")


def test_tail_bytes_command_accepts_a_large_byte_budget() -> None:
    command = ReadOnlyPolicy.build_tail_bytes_command(
        "../logs/example-shop/transfer.log", 10_485_760
    )

    assert command == "tail -c 10485760 -- ../logs/example-shop/transfer.log"


@pytest.mark.parametrize("max_bytes", [0, -1, True])
def test_tail_bytes_command_rejects_invalid_byte_limits(max_bytes: int) -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        ReadOnlyPolicy.build_tail_bytes_command("/var/log/app.log", max_bytes)


def test_tail_bytes_command_rejects_command_shaped_paths() -> None:
    with pytest.raises(ReadOnlyViolation):
        ReadOnlyPolicy.build_tail_bytes_command("rm /var/log/app.log", 100)


def test_raw_ssh_commands_are_not_accepted() -> None:
    with pytest.raises(ReadOnlyViolation):
        validate_read_only_command("tail --lines 100 -- /var/log/app.log")


@pytest.mark.parametrize(
    "command",
    [
        "rm /var/log/app.log",
        "sudo tail /var/log/app.log",
        "tail --lines 10 -- /var/log/app.log > /tmp/copy.log",
        "tail --lines 10 -- /var/log/app.log | cat",
        "tail --lines $(cat /tmp/lines) -- /var/log/app.log",
        "./cleanup.sh",
        "arbitrary-command /var/log/app.log",
    ],
)
def test_legacy_raw_commands_are_rejected(command: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        validate_read_only_command(command)


@pytest.mark.parametrize(
    "path",
    [
        "rm /var/log/app.log",
        "mv /var/log/app.log /tmp/app.log",
        "cp /var/log/app.log /tmp/app.log",
        "touch /tmp/app.log",
        "chmod 644 /var/log/app.log",
        "chown app /var/log/app.log",
        "mkdir /tmp/logs",
        "truncate -s 0 /var/log/app.log",
        "tee /tmp/app.log",
        "sudo tail /var/log/app.log",
        "/var/log/app.log > /tmp/copy.log",
        "/var/log/app.log >> /tmp/copy.log",
        "/var/log/app.log < /tmp/input.log",
        "/var/log/app.log | cat",
        "/var/log/app.log && cat /etc/passwd",
        "/var/log/app.log || cat /etc/passwd",
        "/var/log/app.log; cat /etc/passwd",
        "/var/log/app.log & cat /etc/passwd",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        "python cleanup.py",
        "bash cleanup.sh",
        "./cleanup.sh",
        "uptime",
        "/var/log/app.log\nrm /var/log/app.log",
        "/var/log/app\x00.log",
    ],
)
def test_command_shaped_or_unsafe_paths_are_rejected(path: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        ReadOnlyPolicy.validate_path(path)


def test_file_check_command_does_not_follow_symlinks() -> None:
    command = ReadOnlyPolicy.build_file_check_command("/var/log/store front/app.log")

    assert command == (
        "find '/var/log/store front/app.log' -maxdepth 0 -printf '%y %s %T@\\n'"
    )


def test_file_check_command_also_checks_parent_folders() -> None:
    command = ReadOnlyPolicy.build_file_check_command(
        "/srv/shop/var/log/app.log", ["/srv/shop/var", "/srv/shop/var/log"]
    )

    assert command == (
        "find /srv/shop/var /srv/shop/var/log /srv/shop/var/log/app.log "
        "-maxdepth 0 -printf '%y %s %T@\\n'"
    )


def test_file_check_command_bounds_the_number_of_parent_folders() -> None:
    with pytest.raises(ReadOnlyViolation):
        ReadOnlyPolicy.build_file_check_command(
            "/a/app.log", [f"/a/{index}" for index in range(40)]
        )


@pytest.mark.parametrize(
    "path", ["/var/log/app.log; rm -rf /", "var/log/app.log", "-delete"]
)
def test_file_check_command_rejects_unsafe_or_relative_paths(path: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        ReadOnlyPolicy.build_file_check_command(path)


def test_list_command_is_fixed_non_recursive_and_regular_files_only() -> None:
    command = ReadOnlyPolicy.build_list_command(
        "/srv/example-shop/var/log", "transfer-*.log"
    )

    assert command == (
        "find /srv/example-shop/var/log -maxdepth 1 -type f "
        "-name 'transfer-*.log' -printf '%T@ %s %f\\n'"
    )


@pytest.mark.parametrize(
    "directory",
    [
        "var/log",
        "-delete",
        "/var/log; rm -rf /",
        "/var/log $(id)",
        "/var/log\n/etc",
    ],
)
def test_list_command_rejects_unsafe_directories(directory: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        ReadOnlyPolicy.build_list_command(directory, "transfer-*.log")


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        "*/*.log",
        "../*.log",
        "..",
        "transfer-*.log -delete",
        "transfer-*.log;id",
        "$(id)*.log",
        "-exec",
        "transfer-[0-9].log",
        "**.log",
    ],
)
def test_list_command_rejects_unsafe_patterns(pattern: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        ReadOnlyPolicy.build_list_command("/var/log", pattern)


@pytest.mark.parametrize("pattern", ["transfer-*.log", "system.log", "cron-?.log"])
def test_glob_patterns_with_only_safe_characters_are_accepted(pattern: str) -> None:
    assert ReadOnlyPolicy.validate_glob_pattern(pattern) == pattern
