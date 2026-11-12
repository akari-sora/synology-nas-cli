"""Offline, advisory-scoped fixed-build checks; never a claim of overall NAS safety."""

from __future__ import annotations

import re

# Synology-SA-26:13 (2026-09-18). (branch, build, update, release or None).
# Patched means the advisory's named release at that build/update, not a higher
# micro version: 7.3.2-86009 Update 3 is still short of Update 4, and 7.4.1-1 is
# not 7.4-90075. DSM 7.1 and older are not listed.
SA_26_13 = {
    "url": "https://www.synology.com/en-global/security/advisory/Synology_SA_26_13",
    "fixed": [
        ("7.4", 90075, 0, None),
        ("7.3", 86009, 4, "7.3.2"),
        ("7.2.2", 72806, 9, None),
        ("7.2.1", 69057, 12, None),
    ],
}

# Synology-SA-26:19 revision 1, published 2026-11-10; checked 2026-11-11.
# https://www.synology.com/en-global/security/advisory/Synology_SA_26_19
# (branch, build, update, release). release is the product version the advisory
# names ("or above"); None when the branch prefix is already that version
# (7.2.1, 7.2.2). An older micro on the same branch stays vulnerable.
SA_26_19 = {
    "url": "https://www.synology.com/en-global/security/advisory/Synology_SA_26_19",
    "published": "2026-11-10",
    "checked": "2026-11-11",
    "cves": ["CVE-2026-76954", "CVE-2026-85101"],
    "fixed": [
        ("7.4", 90080, 1, "7.4.1"),
        ("7.3", 86009, 5, "7.3.2"),
        ("7.2.2", 72806, 10, None),
        ("7.2.1", 69057, 13, None),
    ],
}

# Synology-SA-26:18 revision 1, published 2026-11-10 together with SA-26:19
# (25 CVEs; with SA-26:19's two, the "27 DSM vulnerabilities" of 2026-11-10).
# Only DSM 7.4 and 7.3 are listed; older branches the advisory does not list
# are reported as not affected (`unlisted_below`), newer ones stay unknown.
SA_26_18 = {
    "url": "https://www.synology.com/en-global/security/advisory/Synology_SA_26_18",
    "published": "2026-11-10",
    "checked": "2026-11-12",
    "cves": ["CVE-2026-124993", "CVE-2026-13656", "CVE-2026-13672", "CVE-2026-15198", "CVE-2026-15201",
             "CVE-2026-16550", "CVE-2026-18596", "CVE-2026-18633", "CVE-2026-18792", "CVE-2026-19048",
             "CVE-2026-19414", "CVE-2026-19833", "CVE-2026-74850", "CVE-2026-74857", "CVE-2026-75785",
             "CVE-2026-77738", "CVE-2026-81557", "CVE-2026-81558", "CVE-2026-81559", "CVE-2026-81584",
             "CVE-2026-85098", "CVE-2026-86343", "CVE-2026-87801", "CVE-2026-88266", "CVE-2026-92379"],
    "fixed": [
        ("7.4", 90080, 1, "7.4.1"),
        ("7.3", 86009, 5, "7.3.2"),
    ],
    "unlisted_below": (7, 3, 0),
}

# Synology-SA-26:14 ("PHP2Shell", CVE-2026-109618/109619), revision 3 (2026-10-29).
# A fixed version is a string, None (end of life, no fix), or a list of
# (lowest DSM product version, fixed package version), highest DSM first:
# Synology builds the same fix separately for DSM 7.2+, 7.0-7.1 and 6.2.
SA_26_14 = {
    "url": "https://www.synology.com/en-global/security/advisory/Synology_SA_26_14",
    "fixed": {
        "Calendar": [((7, 2), "3.0.4-21435"), ((7, 0), "2.4.8-10948"), ((6, 2), "2.4.8-0948")],
        "MailStation": [((7, 2), "30000002.3.19-20333"), ((7, 0), "30000002.3.19-10333"),
                        ((6, 2), "30000002.3.19-0333")],
        "PHP7.3": None,
        "PHP7.4": [((7, 2), "7.4.33-0131"), ((7, 0), "7.4.33-0122"), ((6, 2), "7.4.33-0010")],
        "PHP8.0": [((7, 2), "8.0.30-0122"), ((7, 0), "8.0.30-0104")],
        "PHP8.1": "8.1.34-0120",
        "PHP8.2": "8.2.35-0171",
        "PHP8.3": "8.3.36-0051",
        "PHP8.4": "8.4.27-0051",
    },
}

# Synology-SA-26:17 ("Plex2Shell", CVE-2026-96656), revision 1 (2026-11-08).
SA_26_17 = {
    "url": "https://www.synology.com/en-global/security/advisory/Synology_SA_26_17",
    "fixed": {
        "PlexMediaServer": [((7, 3), "1.43.5.11079-720011079"), ((7, 2), "1.43.5.11079-700011079")],
    },
}

PACKAGE_ADVISORIES = {"sa_26_14": SA_26_14, "sa_26_17": SA_26_17}

DSM_ADVISORIES = {"sa_26_13": SA_26_13, "sa_26_18": SA_26_18, "sa_26_19": SA_26_19}
_DSM_RE = re.compile(
    r"(?:DSM\s+)?(\d+)\.(\d+)(?:\.(\d+))?-(\d+)(?:(?:\s+Update\s+|-)(\d+))?"
)
_STATUS_ORDER = ("vulnerable", "no_fix_for_branch", "unknown", "patched", "not_affected")
_OK = ("patched", "not_affected")


def _label(advisory: str) -> str:
    return advisory.upper().replace("_", "-", 1).replace("_", ":", 1)


def _rows(table: dict):
    """(prefix, build, update, release or None), longer prefixes first."""
    rows = []
    for row in table["fixed"]:
        if len(row) == 3:
            prefix, build, update = row
            release = None
        else:
            prefix, build, update, release = row
        rows.append((prefix, build, update, release))
    rows.sort(key=lambda r: r[0].count("."), reverse=True)
    return rows


def parse_dsm(firmware_ver: str):
    """Accept DSM's display form and Synology's release form, but not partial input."""
    if not isinstance(firmware_ver, str):
        return None
    m = _DSM_RE.fullmatch(firmware_ver.strip())
    if not m:
        return None
    major, minor, micro, build, update = m.groups()
    return {
        "branch3": f"{major}.{minor}.{micro or 0}",
        "branch2": f"{major}.{minor}",
        "build": int(build),
        "update": int(update or 0),
    }


def _branch_match(v: dict, prefix: str) -> bool:
    if prefix.count(".") >= 2:
        return v["branch3"] == prefix
    return v["branch2"] == prefix


def _branch_tuple(branch3: str) -> tuple:
    return tuple(int(x) for x in branch3.split("."))


def _match_row(v: dict, table: dict):
    """The advisory row for this product version, longest prefix first."""
    return next((row for row in _rows(table) if _branch_match(v, row[0])), None)


def _update_gap(v: dict, row) -> bool:
    """True when row is fixed by an Update on the build already installed.

    That fix ships as an Update pack, not a full image: `nas upgrade` finds and
    verifies it (or DSM installs it from Control Panel > Update & Restore). A
    release requirement must already be met: an Update on 7.4.0-90080 does not
    satisfy an advisory fixed in 7.4.1-90080-1.
    """
    _prefix, build, update, release = row
    if v["build"] != build or v["update"] >= update:
        return False
    return not release or v["branch3"] == release


def _meets(v: dict, build: int, update: int, release) -> bool:
    if release:
        current = tuple(int(x) for x in v["branch3"].split("."))
        minimum = tuple(int(x) for x in release.split("."))
        if current != minimum:
            return current > minimum
    return (v["build"], v["update"]) >= (build, update)


def dsm_advisory_verdict(firmware_ver: str, advisory: str) -> dict:
    """One advisory only. A branch that is not listed is never called patched."""
    table = DSM_ADVISORIES[advisory]
    label = _label(advisory)
    meta = {"advisory": label, "url": table["url"]}
    if table.get("cves"):
        meta["cves"] = list(table["cves"])
    v = parse_dsm(firmware_ver)
    if not v:
        return dict(meta, status="unknown",
                    note="cannot parse DSM version; verify it in Control Panel > Update & Restore")
    match = _match_row(v, table)
    if match is None:
        branch = tuple(int(x) for x in v["branch3"].split("."))
        if table.get("unlisted_below") and branch < table["unlisted_below"]:
            listed = ", ".join(f"DSM {r[0]}" for r in table["fixed"])
            return dict(meta, status="not_affected",
                        note=f"DSM {v['branch3']} is not listed in {label} (affected: {listed})")
        status = "no_fix_for_branch" if branch < (7, 2, 1) else "unknown"
        if status == "no_fix_for_branch":
            note = (f"DSM {v['branch3']} is not covered by {label}; no patch is listed for it. "
                    "Upgrade to a fixed branch (`nas upgrade --dry-run` shows the newest build for this model).")
        else:
            note = (f"DSM {v['branch3']} has no fixed release listed in {label}; "
                    "check the official advisory and this model's supported upgrade path")
        return dict(meta, status=status, note=note)
    prefix, build, update, release = match
    shown = release or prefix
    fixed_in = f"{shown}-{build}" + (f"-{update}" if update else "")
    patched = _meets(v, build, update, release)
    out = dict(meta, status="patched" if patched else "vulnerable", fixed_in=fixed_in)
    if not patched:
        if _update_gap(v, match):
            # An Update on the build already installed: an Update pack, which
            # `nas upgrade` discovers and verifies; the control panel is the fallback.
            out["note"] = (f"{label}: this build needs Update {update}: `nas upgrade --dry-run` finds the "
                           "verified Update pack, `nas upgrade --install-update --yes` installs it "
                           "(or Control Panel > Update & Restore)")
        else:
            out["note"] = (f"{label}: update to {fixed_in} or later "
                           "(`nas upgrade --dry-run` shows the newest build for this model)")
    return out


def update_gap_only(firmware_ver: str) -> bool:
    """True when every open advisory is fixed by an Update on the build already installed.

    Then a full-build upgrade is the wrong tool: either the Update pack route
    (`nas upgrade --install-update`) or Control Panel > Update & Restore.
    False as soon as one open advisory needs a different build, branch or release.
    """
    v = parse_dsm(firmware_ver)
    if not v:
        return False
    open_rows = []
    for key, table in DSM_ADVISORIES.items():
        if dsm_advisory_verdict(firmware_ver, key)["status"] in _OK:
            continue
        row = _match_row(v, table)
        if row is None or not _update_gap(v, row):
            return False
        open_rows.append(row)
    return bool(open_rows)


def needed_update(firmware_ver: str):
    """Highest Update number that would close every open advisory on this build.

    None unless update_gap_only(): a release-gated row (e.g. 7.4.0 for a fix in
    7.4.1) or a different build needs a full upgrade, not an Update pack.
    """
    v = parse_dsm(firmware_ver)
    if not v:
        return None
    need = None
    for key, table in DSM_ADVISORIES.items():
        if dsm_advisory_verdict(firmware_ver, key)["status"] in _OK:
            continue
        row = _match_row(v, table)
        if row is None or not _update_gap(v, row):
            return None
        _prefix, _build, update, _release = row
        need = update if need is None else max(need, update)
    return need


def dsm_verdict(firmware_ver: str) -> dict:
    """Every tracked DSM advisory. status is patched only when each of them is."""
    results = {key: dsm_advisory_verdict(firmware_ver, key) for key in DSM_ADVISORIES}
    status = next(s for s in _STATUS_ORDER if any(v["status"] == s for v in results.values()))
    if status == "not_affected":
        status = "patched"          # nothing open: the aggregate only says patched or not
    out = {"status": status, "advisories": results}
    if status != "patched":
        current = parse_dsm(firmware_ver)
        for key in ("sa_26_19", "sa_26_18", "sa_26_13"):
            v = results[key]
            if v["status"] in _OK or not v.get("fixed_in"):
                continue
            target = parse_dsm("DSM " + v["fixed_in"])
            if current and target and _branch_tuple(target["branch3"]) < _branch_tuple(current["branch3"]):
                continue            # that fix belongs to an older product version than this box runs
            out["fixed_in"] = v["fixed_in"]
            break
        # advisories that need the same step share one note: "SA-26:18, SA-26:19: this build needs Update 1..."
        advice = {}
        for v in results.values():
            if v["status"] in _OK or not v.get("note"):
                continue
            label, note = v.get("advisory") or "", v["note"]
            text = note[len(label) + 2:] if label and note.startswith(label + ": ") else note
            advice.setdefault(text, []).append(label if note.startswith(label + ": ") else "")
        notes = []
        for text, labels in advice.items():
            named = ", ".join(x for x in labels if x)
            notes.append(f"{named}: {text}" if named else text)
        if notes:
            text = notes[0]
            for n in notes[1:]:
                text += (" " if text.endswith(".") else "; ") + n
            out["note"] = text
    return out


def dsm_detail(firmware_ver: str, report: dict) -> str:
    """Human text for one DSM build: each advisory by name, then the note when not fully patched."""
    bits = "; ".join(advisory_phrase(report["advisories"][k]) for k in DSM_ADVISORIES if k in report["advisories"])
    detail = f"{firmware_ver}: {bits}"
    if report.get("status") != "patched" and report.get("note"):
        detail += ". " + report["note"]
    return detail


def advisory_phrase(v: dict) -> str:
    """One advisory, named. Never describes a different advisory as patched."""
    label = v.get("advisory") or "DSM"
    if v.get("status") == "patched" and v.get("fixed_in"):
        return f"{label} patched (fixed in {v['fixed_in']})"
    if v.get("status") == "vulnerable" and v.get("fixed_in"):
        return f"{label} vulnerable (fixed in {v['fixed_in']})"
    if v.get("status") == "not_affected":
        return f"{label} not affected"
    return f"{label} {v.get('status')}"


def _vtuple(s: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))


def _fixed_for_dsm(fixed, dsm: tuple | None):
    """The fixed version that applies on this DSM (major, minor); a list is per-DSM, highest first."""
    if not isinstance(fixed, list):
        return fixed
    if dsm is None:
        return fixed[0][1]          # DSM unknown: the newest build's fix (may over-report, never under)
    for low, version in fixed:
        if dsm >= low:
            return version
    return False                    # older than every DSM the advisory lists


def package_verdict(pkg_id: str, version: str, firmware_ver: str | None = None) -> dict | None:
    """None when the package is not named in a tracked package advisory (SA-26:14, SA-26:17).

    `firmware_ver` picks the per-DSM fix: Synology builds SA-26:14's Calendar,
    MailStation and PHP 7.4/8.0 fixes separately for DSM 7.2+, 7.0-7.1 and 6.2.
    """
    v = parse_dsm(firmware_ver) if firmware_ver else None
    dsm = tuple(int(x) for x in v["branch2"].split(".")) if v else None
    for key, table in PACKAGE_ADVISORIES.items():
        if pkg_id not in table["fixed"]:
            continue
        meta = {"advisory": _label(key), "url": table["url"]}
        fixed = _fixed_for_dsm(table["fixed"][pkg_id], dsm)
        if fixed is None:
            return dict(meta, status="no_fix", note="end of life; uninstall")
        if fixed is False:
            return dict(meta, status="unknown", note=f"{meta['advisory']} lists no fix for DSM {v['branch2']}; "
                                                     "update DSM or uninstall the package")
        if _vtuple(version) >= _vtuple(fixed):
            return dict(meta, status="patched", fixed_in=fixed)
        return dict(meta, status="vulnerable", fixed_in=fixed)
    return None
