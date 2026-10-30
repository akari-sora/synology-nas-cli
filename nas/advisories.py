"""Known fixed builds, checked against what the NAS reports."""

from __future__ import annotations

import re

# Synology-SA-26:13 (2026-09-18): CVE-2026-13639 / CVE-2026-13684, used by
# the C3RB3R (.L0CK3D) campaign. Branch prefix -> (build, update) that fixes it.
# DSM 7.1.x and older are not listed: that branch gets no fix.
SA_26_13 = {
    "url": "https://www.synology.com/en-global/security/advisory/Synology_SA_26_13",
    "fixed": [
        ("7.4", 90075, 0),
        ("7.3", 86009, 4),
        ("7.2.2", 72806, 9),
        ("7.2.1", 69057, 12),
    ],
}

# Synology-SA-26:14 "PHP2Shell" (2026-10-22, rev 2026-10-26): package -> fixed version,
# None means no fix (end of life, uninstall).
SA_26_14 = {
    "url": "https://www.synology.com/en-global/security/advisory/Synology_SA_26_14",
    "fixed": {
        "Calendar": "3.0.4-21435",
        "MailStation": "30000002.3.19-20333",
        "PHP7.3": None,
        "PHP7.4": "7.4.33-0131",
        "PHP8.0": "8.0.30-0122",
        "PHP8.1": "8.1.34-0120",
        "PHP8.2": "8.2.35-0171",
        "PHP8.3": "8.3.36-0051",
        "PHP8.4": "8.4.27-0051",
    },
}

_DSM_RE = re.compile(r"DSM\s+(\d+)\.(\d+)(?:\.(\d+))?-(\d+)(?:\s+Update\s+(\d+))?")


def parse_dsm(firmware_ver: str):
    m = _DSM_RE.search(firmware_ver or "")
    if not m:
        return None
    major, minor, micro, build, update = m.groups()
    return {
        "branch3": f"{major}.{minor}.{micro or 0}",
        "branch2": f"{major}.{minor}",
        "build": int(build),
        "update": int(update or 0),
    }


def dsm_verdict(firmware_ver: str) -> dict:
    v = parse_dsm(firmware_ver)
    if not v:
        return {"status": "unknown", "note": f"cannot parse {firmware_ver!r}"}
    match = None
    for prefix, build, update in SA_26_13["fixed"]:
        if prefix.count(".") == 2 and prefix == v["branch3"]:
            match = (prefix, build, update)
            break
    if not match:
        for prefix, build, update in SA_26_13["fixed"]:
            if prefix.count(".") == 1 and prefix == v["branch2"]:
                match = (prefix, build, update)
                break
    if not match:
        return {
            "status": "no_fix_for_branch",
            "note": f"DSM {v['branch3']} is not covered by SA-26:13; no patch will come for it. "
                    "Upgrade to a fixed branch (`nas upgrade --dry-run` shows the newest build for this model).",
        }
    prefix, build, update = match
    fixed_in = f"{prefix}-{build}" + (f"-{update}" if update else "")
    if (v["build"], v["update"]) >= (build, update):
        return {"status": "patched", "fixed_in": fixed_in}
    return {"status": "vulnerable", "fixed_in": fixed_in,
            "note": f"update to {fixed_in} or later (`nas upgrade --dry-run` shows the newest build for this model)"}


def _vtuple(s: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))


def package_verdict(pkg_id: str, version: str) -> dict | None:
    """None when the package is not named in SA-26:14."""
    if pkg_id not in SA_26_14["fixed"]:
        return None
    fixed = SA_26_14["fixed"][pkg_id]
    if fixed is None:
        return {"status": "no_fix", "note": "end of life; uninstall"}
    if _vtuple(version) >= _vtuple(fixed):
        return {"status": "patched", "fixed_in": fixed}
    return {"status": "vulnerable", "fixed_in": fixed}
