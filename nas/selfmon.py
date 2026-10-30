"""`nas alert-deploy`: run `nas alert` on the NAS itself and push changes to a webhook.

What it sets up, from a computer with --backend password (paths and names come
from the "deploy" section of the config):

- <root_dir>/app: this package (nas/*.py), a launcher (bin/nas) and config.json
  (the effective config without credentials/webhook/session), from a tarball
  whose SHA-256 the install task checks before extracting.
- <root_dir>/webhook.json (mode 600): {"url", "header"} from the "webhook"
  section of the config (1Password item, JSON file, or command).
- <root_dir>/state/: baseline.json, baseline-pushed.json, last-run.txt.
- DSM Task Scheduler task <task_name> (owner root, every --interval minutes):
  `NAS_CONFIG=<root_dir>/app/config.json python3 <root_dir>/app/bin/nas --backend local
  alert --push ...`. It always exits 0 so that DSM's own "task failed"
  notification never fires on a warning.
- DSM notification webhook <dsm_webhook_name> (Control Panel > Notification >
  Webhooks, rule template <dsm_webhook_template>): DSM's built-in warning/error
  events go to the same URL as {"text": "<prefix> ..."}.

<root_dir> must not be inside a shared folder: any account that can write a
shared folder could then change code that runs as root. The tarball is staged
in <stage_dir> (a shared folder), copied into <root_dir> by root, hashed and
only then extracted.

Root-owned tasks need SYNO.Core.User.PasswordConfirm (the account password
from the credential chain) each time one is created.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import re
import secrets
import shlex
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.parse

from . import config
from .backends import NasError
from .commands import need

PKG = os.path.dirname(os.path.abspath(__file__))

LAUNCHER = b"""#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from nas.cli import main  # noqa: E402

sys.exit(main())
"""


def _deploy() -> dict:
    return config.get()["deploy"]


def deployed_config() -> dict:
    """The config the NAS-side runs use: everything except where secrets come from."""
    cfg = copy.deepcopy(config.get())
    for k in ("credentials", "webhook", "session"):
        cfg.pop(k, None)
    return cfg


def _payload() -> bytes:
    buf = io.BytesIO()

    def add(name: str, data: bytes, mode: int = 0o644):
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(data), mode, 0
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        tar.addfile(info, io.BytesIO(data))

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        add("bin/nas", LAUNCHER, 0o755)
        for n in sorted(os.listdir(PKG)):
            if n.endswith(".py"):
                with open(os.path.join(PKG, n), "rb") as f:
                    add(f"nas/{n}", f.read())
        add("config.json", (json.dumps(deployed_config(), ensure_ascii=False, indent=2) + "\n").encode())
    return buf.getvalue()


def _check_hook(hook: dict, where: str) -> dict:
    url, header = hook.get("url") or "", hook.get("header") or ""
    if not url.startswith("https://") or ":" not in header:
        raise NasError(f"{where}: needs an https:// URL and a header line 'Name: value' "
                       "(DSM's notification webhook only accepts HTTPS)")
    return {"url": url, "header": header}


def webhook(s, override: str | None = None) -> dict:
    """{"url", "header"} from --webhook-item (op://VAULT/ITEM) or the config "webhook" section."""
    w = config.get()["webhook"]
    item = override or w["op_item"]
    if item:
        d = s.backend.op_item_json(item)
        url = next((u.get("href") for u in d.get("urls") or [] if u.get("href")), "")
        header = next((f.get("value") for f in d.get("fields") or []
                       if f.get("label") == w["op_header_field"]), "")
        return _check_hook({"url": url, "header": header},
                           f"1Password item {item} (website = URL, field {w['op_header_field']!r} = header)")
    if w["file"]:
        path = config.path(w["file"])
        try:
            with open(path, encoding="utf-8") as f:
                return _check_hook(json.load(f), path)
        except (OSError, ValueError) as e:
            raise NasError(f"webhook.file {path}: {e}")
    if w["command"]:
        import subprocess
        p = subprocess.run(w["command"], shell=True, capture_output=True, text=True, timeout=60)
        try:
            return _check_hook(json.loads(p.stdout), "webhook.command")
        except ValueError:
            raise NasError(f"webhook.command did not print JSON (exit {p.returncode})")
    raise NasError("no webhook configured: set webhook.op_item, webhook.file or webhook.command "
                   "(or pass --webhook-item op://VAULT/ITEM)")


def share_real_path(s, fs_path: str) -> str:
    """Path on the NAS's disk of a File Station path (/share/sub/dir)."""
    fs_path = "/" + fs_path.strip("/")
    share = fs_path.split("/")[1]
    d = need("SYNO.FileStation.List", s.call("SYNO.FileStation.List", "list_share", version=2,
                                             params={"additional": ["real_path"]})) or {}
    real = next(((x.get("additional") or {}).get("real_path") for x in d.get("shares") or []
                 if x.get("name") == share), None)
    if not real:
        raise NasError(f"shared folder {share!r} not found (or real_path not reported)")
    return real.rstrip("/") + fs_path[len(share) + 1:]


def _stage(s) -> tuple:
    """(FileStation path, path on the NAS's disk) of the staging folder."""
    stage = _deploy()["stage_dir"].rstrip("/")
    if not stage.startswith("/") or stage.count("/") < 2:
        raise NasError("deploy.stage_dir must be a folder inside a shared folder, e.g. /SHARE/.nas-cli-deploy "
                       "(FileStation path); the account needs write access to that share")
    share = stage.split("/")[1]
    d = need("SYNO.FileStation.List", s.call("SYNO.FileStation.List", "list_share", version=2,
                                             params={"additional": ["real_path"]})) or {}
    real = next(((x.get("additional") or {}).get("real_path") for x in d.get("shares") or []
                 if x.get("name") == share), None)
    if not real:
        raise NasError(f"shared folder {share!r} of deploy.stage_dir not found (or real_path not reported)")
    return stage, real.rstrip("/") + stage[len(share) + 1:]


def _schedule(every_min: int) -> dict:
    # every N minutes, all day, every day (DSM's own encoding, see N4S4/synology-api task_scheduler.py)
    return {"date_type": 0, "week_day": "0,1,2,3,4,5,6", "hour": 0, "minute": 0, "repeat_hour": 0,
            "repeat_min": every_min, "last_work_hour": 23, "repeat_date": 1001, "monthly_week": "[]"}


def _tasks(s) -> list[dict]:
    d = need("SYNO.Core.TaskScheduler", s.call("SYNO.Core.TaskScheduler", "list", version=3, params={
        "sort_by": "name", "sort_direction": "ASC", "offset": 0, "limit": 200}))
    return d.get("tasks") or []


def _delete_task(s, task_id: int) -> None:
    need("SYNO.Core.TaskScheduler", s.call("SYNO.Core.TaskScheduler", "delete", version=2,
                                           params={"tasks": [{"id": task_id, "real_owner": "root"}]}))


def _create_root_task(s, name: str, script: str, enable: bool, schedule: dict) -> int:
    extra = {"notify_enable": False, "notify_mail": "", "notify_if_error": False, "script": script}
    d = need("SYNO.Core.TaskScheduler.Root", s.call("SYNO.Core.TaskScheduler.Root", "create", version=4, params={
        "name": name, "real_owner": "root", "owner": "root", "enable": enable, "type": "script",
        "schedule": json.dumps(schedule), "extra": json.dumps(extra),
        "SynoConfirmPWToken": s.backend.confirm_password()}))
    return d["id"]


def run_root_script(s, name: str, script: str, done=None, timeout: float = 30) -> bool:
    """Run `script` once as root through a temporary DSM Task Scheduler task.

    For calls DSM refuses from a password session (e.g. SYNO.Core.User set answers 105 even after
    PasswordConfirm) but accepts from `synowebapi` as root. The task is created disabled, started
    with TaskScheduler run v2, and deleted afterwards (task scripts are visible to every
    administrator). `done(s)` is polled until true or `timeout`; returns its last answer.
    """
    if s.backend_name != "password":
        raise NasError("running a root task needs --backend password (DSM asks for the password to create it)")
    for t in _tasks(s):
        if t.get("name") == name:
            _delete_task(s, t["id"])
    tid = _create_root_task(s, name, script.rstrip("\n") + "\nexit 0\n", False, _schedule(10))
    ok = False
    try:
        need("SYNO.Core.TaskScheduler", s.call("SYNO.Core.TaskScheduler", "run", version=2,
                                               params={"tasks": [{"id": tid, "real_owner": "root"}]}))
        deadline = time.time() + timeout
        while True:
            time.sleep(2)
            ok = bool(done(s)) if done else True
            if ok or time.time() > deadline:
                break
    finally:
        err = _delete_task_checked(s, tid)
        if err:
            msg = (f"could not delete the temporary root task {name!r} (id {tid}): {err}. "
                   "Delete it in Control Panel > Task Scheduler.")
            if sys.exc_info()[0] is None:
                raise NasError(msg)
            print(f"nas: WARNING: {msg}", file=sys.stderr)
    return ok


def _delete_task_checked(s, tid: int) -> str | None:
    """Delete a task, retry once, and confirm it is gone. None on success, else the reason."""
    last = None
    for _ in range(2):
        try:
            _delete_task(s, tid)
        except NasError as e:
            last = str(e)
        try:
            if not any(t.get("id") == tid for t in _tasks(s)):
                return None
        except NasError as e:
            last = str(e)
        time.sleep(1)
    return last or "still listed"


def _read_stage_file(s, stage: str, name: str) -> str | None:
    path = urllib.parse.quote(json.dumps([f"{stage}/{name}"]))
    st, _, body, _ = s.http_raw("/webapi/entry.cgi?api=SYNO.FileStation.Download&version=2&method=download"
                                f"&mode=download&path={path}", timeout=30)
    if st != 200 or body.lstrip().startswith('{"error"'):
        return None
    return body


ROOT_DIR_RE = re.compile(r"^/volume\d+/@[\w.-]+$")


def _install_script(sha: str, webhook_b64: str, root: str, stage_fs: str, token: str) -> str:
    """Root script for the one-off install task.

    Everything root reads comes from a private copy: the staging folder is in
    a shared folder that other accounts may be able to write, so the tarball is
    copied into $D first and only that copy is hashed and extracted. Output goes to $D/result.txt and is
    copied out at the end with O_EXCL|O_NOFOLLOW (nothing pre-planted there is
    followed). The webhook blob comes in on stdin, not on a command line.
    """
    return f"""umask 077
D={shlex.quote(root)}; S={shlex.quote(stage_fs)}
[ -L "$S" ] && {{ echo "staging folder is a symlink"; exit 1; }}
mkdir -p "$D/state" && chmod 700 "$D" || exit 1
exec >"$D/result.txt" 2>&1
fin() {{ rm -f "$S/result.txt"; python3 -I -c 'import os,sys; fd=os.open(sys.argv[2], os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o644); os.write(fd, open(sys.argv[1], "rb").read())' "$D/result.txt" "$S/result.txt"; exit $1; }}
rm -f "$D/payload.tgz"; cp -- "$S/payload.tgz" "$D/payload.tgz" || {{ echo INSTALL_FAILED; fin 1; }}
echo "{sha}  $D/payload.tgz" | sha256sum -c - || {{ echo INSTALL_FAILED; fin 1; }}
rm -rf "$D/app.new"; mkdir "$D/app.new" && tar xzf "$D/payload.tgz" -C "$D/app.new" --no-same-owner || {{ echo INSTALL_FAILED; fin 1; }}
rm -f "$D/payload.tgz"; chown -R root:root "$D/app.new"
if [ -d "$D/app" ]; then echo "--- changes from the previous install"; diff -r "$D/app" "$D/app.new" | head -c 20000; fi
rm -rf "$D/app.old"; if [ -d "$D/app" ]; then mv "$D/app" "$D/app.old"; fi; mv "$D/app.new" "$D/app"
python3 -I -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' > "$D/webhook.json" <<'B64'
{webhook_b64}
B64
chmod 600 "$D/webhook.json"
export NAS_CONFIG="$D/app/config.json"
python3 "$D/app/bin/nas" --version
python3 "$D/app/bin/nas" --backend local alert --state "$D/state/baseline.json" --no-update; echo "alert rc=$?"
echo "DEPLOY_OK {token}"
fin 0
"""


def _run_script(root: str) -> str:
    return (f'D={shlex.quote(root)}\n'
            'NAS_CONFIG="$D/app/config.json" python3 "$D/app/bin/nas" --backend local alert '
            '--state "$D/state/baseline.json" --push "$D/webhook.json" > "$D/state/last-run.txt" 2>&1\n'
            'exit 0\n')


def _dsm_webhook(s, hook: dict, send_test: bool) -> list[str]:
    dep = _deploy()
    PROVIDER_NAME, DSM_TEMPLATE = dep["dsm_webhook_name"], dep["dsm_webhook_template"]
    prefix = dep["dsm_webhook_prefix"] or f"[{config.get()['name']}]"
    tpl = need("SYNO.Core.Notification.Advance.FilterSettings.Template",
               s.call("SYNO.Core.Notification.Advance.FilterSettings.Template", "list", version=1))
    tid = next((t["template_id"] for t in tpl.get("templates") or [] if t.get("name") == DSM_TEMPLATE), None)
    if tid is None:
        raise NasError(f"DSM notification template {DSM_TEMPLATE!r} not found")
    name, value = hook["header"].split(":", 1)
    params = {
        "type": "custom", "port": 0, "template_id": tid, "interval": 0, "req_method": "post",
        "req_header": f"Content-Type:application/json\r{name.strip()}:{value.strip()}\r",
        # a string field whose text is JSON: encode twice, or _encode_params sends it as an object
        "req_param": json.dumps(json.dumps({"text": "@@TEXT@@"})), "needssl": True, "provider": PROVIDER_NAME,
        "use_default_lang": False, "prefix": prefix, "sepchar": " ", "url": hook["url"],
    }
    api = "SYNO.Core.Notification.Push.Webhook.Provider"
    have = need(api, s.call(api, "list", version=2)).get("list") or []
    mine = next((p for p in have if p.get("target_name") == PROVIDER_NAME
                 or (p.get("target_config") or {}).get("provider") == PROVIDER_NAME), None)
    if mine:
        need(api, s.call(api, "set", version=2, params={"profile_id": mine["profile_id"], **params}))
        pid, lines = mine["profile_id"], [f"DSM webhook {PROVIDER_NAME!r} updated (profile {mine['profile_id']})"]
    else:
        need(api, s.call(api, "create", version=2, params=params))
        have = need(api, s.call(api, "list", version=2)).get("list") or []
        pid = next((p["profile_id"] for p in have if p.get("target_name") == PROVIDER_NAME
                    or (p.get("target_config") or {}).get("provider") == PROVIDER_NAME), None)
        lines = [f"DSM webhook {PROVIDER_NAME!r} created (profile {pid}, template {DSM_TEMPLATE})"]
    if send_test and pid is not None:
        need(api, s.call(api, "send_test", version=2, params={"profile_id": pid}))
        lines.append("DSM test notification sent: check the receiver")
    return lines


def deploy(s, args):
    if s.backend_name != "password":
        raise NasError("alert-deploy needs --backend password (it uploads files and confirms the password)")
    dep = _deploy()
    root, task_name, install_task = dep["root_dir"].rstrip("/"), dep["task_name"], dep["install_task_name"]
    if not ROOT_DIR_RE.match(root):
        raise NasError("deploy.root_dir must look like /volumeN/@name (a root-only folder outside the shared "
                       "folders), e.g. /volume1/@nas-alert")
    hook = webhook(s, args.webhook_item)
    stage, stage_fs = _stage(s)
    payload = _payload()
    sha = hashlib.sha256(payload).hexdigest()
    lines = [f"payload {len(payload)} bytes, sha256 {sha[:12]}…"]

    # stage the tarball (checked by hash before root extracts it)
    s.call("SYNO.FileStation.CreateFolder", "create", version=2,
           params={"folder_path": json.dumps([os.path.dirname(stage)]), "name": json.dumps([os.path.basename(stage)]),
                   "force_parent": True})
    tmpdir = tempfile.mkdtemp(prefix="nas-alert-")
    tmp = os.path.join(tmpdir, "payload.tgz")  # FileStation keeps the local file name
    with open(tmp, "wb") as f:
        f.write(payload)
    try:
        up = s.upload("SYNO.FileStation.Upload", "upload", 2,
                      {"path": stage, "create_parents": "true", "overwrite": "true"}, tmp)
    finally:
        shutil.rmtree(tmpdir)
    if not up.get("ok"):
        raise NasError(f"upload to {stage} failed: {up.get('error')}")

    for t in _tasks(s):
        if t.get("name") == install_task:
            _delete_task(s, t["id"])
    webhook_b64 = base64.b64encode(json.dumps(hook).encode()).decode()
    token = secrets.token_hex(8)  # success marker nobody can pre-plant in the staging folder
    ok_mark = f"DEPLOY_OK {token}"
    tid = _create_root_task(s, install_task, _install_script(sha, webhook_b64, root, stage_fs, token), False,
                            _schedule(10))
    try:
        need("SYNO.Core.TaskScheduler", s.call("SYNO.Core.TaskScheduler", "run", version=2,
                                               params={"tasks": [{"id": tid, "real_owner": "root"}]}))
        out = None
        for _ in range(30):
            time.sleep(3)
            out = _read_stage_file(s, stage, "result.txt")
            if out and (ok_mark in out or "INSTALL_FAILED" in out):
                break
    finally:
        # separately: a failure in one must not leave the other (the task script holds the webhook blob)
        left = _delete_task_checked(s, tid)
        try:
            s.call("SYNO.FileStation.Delete", "start", version=2,
                   params={"path": json.dumps([stage]), "recursive": True})
        except NasError as e:
            lines.append(f"WARNING: could not delete {stage}: {e}")
    lines += ["--- install on the NAS ---"] + (out or "(no result.txt)").rstrip().splitlines()
    if left:
        raise NasError("\n".join(lines) + f"\nThe install task {install_task!r} (id {tid}) could not be deleted ({left}) "
                       "and its script contains the webhook key: delete it now in Control Panel > Task Scheduler.")
    if not out or ok_mark not in out:
        raise NasError("install failed:\n" + "\n".join(lines))

    for t in _tasks(s):
        if t.get("name") == task_name:
            _delete_task(s, t["id"])
    interval = args.interval or dep["interval_min"]
    tid = _create_root_task(s, task_name, _run_script(root), True, _schedule(interval))
    lines.append(f"task {task_name!r} (id {tid}, root) runs every {interval} min")

    if not args.no_dsm_webhook:
        lines += _dsm_webhook(s, hook, args.test)
    return lines, {"sha256": sha, "task_id": tid}
