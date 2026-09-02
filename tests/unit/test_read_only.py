import pytest

from ecomops.core.exceptions import ReadOnlyViolation
from ecomops.ssh.read_only import validate_read_only_command


@pytest.mark.parametrize(
    "command",
    [
        "tail -n 100 /var/log/app.log",
        "head -n 20 /var/log/app.log",
        "grep -E 'ERROR|CRITICAL' /var/log/app.log",
        "rg timeout /var/log/app.log",
        "cat /var/log/app.log",
        "stat /var/log/app.log",
    ],
)
def test_read_only_commands_are_accepted(command: str) -> None:
    assert validate_read_only_command(command) == command


@pytest.mark.parametrize(
    "command",
    [
        "rm /var/log/app.log",
        "sudo tail /var/log/app.log",
        "tail /var/log/app.log > /tmp/copy.log",
        "cat /var/log/app.log; systemctl restart nginx",
        "python cleanup.py",
    ],
)
def test_mutating_or_composite_commands_are_rejected(command: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        validate_read_only_command(command)
