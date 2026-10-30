"""Exceptions commands raise for expected, reportable failures. `exit_code` is the process exit status
`cli.main` returns for them (docs/EXIT-CODES.md)."""

from __future__ import annotations

import os
import sys


class NasError(Exception):
    exit_code = 1


class InputRequired(NasError):
    """A prompt or confirmation was needed but input is off (--no-input, NAS_NO_INPUT=1, or no terminal)."""
    exit_code = 3


class AuthFailed(NasError):
    """DSM rejected the sign-in (wrong password, disabled account, 2-step verification)."""
    exit_code = 4


class Blocked(NasError):
    """DSM's AutoBlock has blocked this address (login error 407)."""
    exit_code = 5


class Unreachable(NasError):
    """No origin answered, or DSM is upgrading / not ready (498, 499)."""
    exit_code = 6


class CertificateChanged(NasError):
    """The DSM certificate differs from the one trusted on first use."""
    exit_code = 7


_no_input = False


def set_no_input(value: bool = True) -> None:
    global _no_input
    _no_input = value


def can_prompt() -> bool:
    """False with --no-input, NAS_NO_INPUT=1, or when stdin is not a terminal."""
    if _no_input or os.environ.get("NAS_NO_INPUT", "") not in ("", "0"):
        return False
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False
