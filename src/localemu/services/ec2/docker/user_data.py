"""EC2 user-data translator: from cloud-init input formats to a shell script.

The LocalEmu EC2 base image is intentionally lean (no cloud-init, no python
runtime mandated, no systemd). To match real-AWS user-data semantics
without pulling in cloud-init's ~50 MB Python tree on every container, we
translate user-data into a single ``/bin/sh`` script at instance launch
time and let the container's existing shell run it.

Supported input formats (cloud-init compatible):

* **gzip** — if the bytes start with the gzip magic ``\\x1f\\x8b`` we
  decompress and re-classify the inner payload.
* **shebang script** (``#!...``) — executed as-is.
* **``#cloud-config``** — YAML directives translated to shell.
* **MIME multipart** (``Content-Type: multipart/...``) — walked, each
  supported part is translated and the resulting shell scripts are
  concatenated in the part order. ``text/x-shellscript``,
  ``text/cloud-config``, ``text/cloud-boothook`` and
  ``text/cloud-config-archive`` are supported.
* **``#cloud-boothook``** — treated as a shell script that should run in
  the ``bootcmd`` phase (i.e. before ``runcmd``). Same effect as a
  shebang for our single-shot model.
* **``#include`` / ``#include-once``** — declared as a future
  enhancement; the current build logs a warning and skips the
  directive (it would require network fetches during container start).
* Unknown formats — logged at warning level, written to disk as a
  ``/bin/sh`` script (cloud-init's documented fallback for unknown
  user-data).

Supported ``#cloud-config`` directives (full real-cloud-init grammar for
the common-attack-lab subset):

* ``packages`` — list of package names (each name is a string OR a
  ``[name, version]`` pair). Auto-detects apt/yum/dnf/apk.
* ``package_update`` / ``package_upgrade`` — booleans.
* ``write_files`` — list of ``{path, content, owner, permissions,
  encoding, append}`` dicts. ``encoding`` may be ``b64``, ``base64``,
  ``gz``, ``gzip``, or absent (UTF-8 text).
* ``bootcmd`` — list of commands; runs before ``runcmd``.
* ``runcmd`` — list of commands. Each item is either a string (run via
  ``sh -c``) or a list (exec directly, argv).
* ``users`` — list of user definitions; supports ``name``, ``shell``,
  ``groups``, ``sudo``, ``ssh_authorized_keys``, ``lock_passwd``,
  ``passwd`` (already-hashed), ``homedir``, ``no_create_home``.
* ``ssh_authorized_keys`` — list of keys appended to
  ``/root/.ssh/authorized_keys``.
* ``disable_root`` — bool, toggles ``PermitRootLogin`` in sshd_config.
* ``ssh_pwauth`` — bool, toggles ``PasswordAuthentication`` in
  sshd_config.
* ``hostname`` — string, written to ``/etc/hostname`` and applied via
  ``hostname`` if available.
* ``manage_etc_hosts`` — bool / ``"localhost"``, rewrites
  ``/etc/hosts`` with the instance hostname.
* ``final_message`` — string, printed at the tail of
  ``/var/log/cloud-init-output.log``.

Explicit non-goals (logged + skipped):

* ``text/part-handler`` — arbitrary Python evaluation.
* ``text/upstart-job`` — upstart was superseded by systemd; modern AMIs
  no longer ship the upstart init system.
* ``text/jinja2`` — Jinja templates require the cloud-init datasource.

The translator is **deterministic and side-effect-free** at Python
level: it takes bytes in, returns shell-script text out. All container
mutations happen when the shell script later executes inside the
instance.
"""
from __future__ import annotations

import base64
import email
import email.policy
import gzip
import json
import logging
import shlex
from dataclasses import dataclass, field
from enum import StrEnum

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


class UserDataFormat(StrEnum):
    """How the user-data payload was identified."""
    SHEBANG = "shebang"
    CLOUD_CONFIG = "cloud-config"
    CLOUD_BOOTHOOK = "cloud-boothook"
    MIME_MULTIPART = "mime-multipart"
    INCLUDE_URL = "include-url"
    UNKNOWN = "unknown"
    EMPTY = "empty"


@dataclass
class TranslatedUserData:
    """Result of translating a raw user-data blob.

    Attributes:
        format: How the payload was identified.
        shell_script: Shell-script text to write to disk + execute in the
            instance. Always a runnable ``/bin/sh`` document; empty
            payloads produce a no-op script.
        warnings: Diagnostic notes (unrecognised MIME parts, unknown
            cloud-config directives, etc.). Surfaced to the instance via
            ``/var/log/cloud-init.log`` and printed at translation time
            so issues are visible without execing in.
    """

    format: UserDataFormat
    shell_script: str
    warnings: list[str] = field(default_factory=list)


def build_cloud_init_shell(raw_user_data: bytes | str | None) -> TranslatedUserData:
    """Translate a raw user-data payload into an executable shell script.

    The returned :class:`TranslatedUserData` is safe to drop into the
    container at ``/var/lib/localemu/user-data.sh`` and ``exec``. The
    script is guarded so a second run (e.g. on ``docker restart``) is a
    no-op: real cloud-init has the same once-only contract.
    """
    if raw_user_data is None:
        return TranslatedUserData(UserDataFormat.EMPTY, _wrap_empty(), [])
    if isinstance(raw_user_data, str):
        raw_user_data = raw_user_data.encode("utf-8")
    if not raw_user_data:
        return TranslatedUserData(UserDataFormat.EMPTY, _wrap_empty(), [])

    payload, _gunzipped = _maybe_gunzip(raw_user_data)
    fmt = classify(payload)
    warnings: list[str] = []

    if fmt is UserDataFormat.SHEBANG:
        body = _shebang_body(payload)
    elif fmt is UserDataFormat.CLOUD_CONFIG:
        body = _cloud_config_body(payload, warnings)
    elif fmt is UserDataFormat.CLOUD_BOOTHOOK:
        body = _cloud_boothook_body(payload)
    elif fmt is UserDataFormat.MIME_MULTIPART:
        body = _mime_body(payload, warnings)
    elif fmt is UserDataFormat.INCLUDE_URL:
        body = _include_unsupported_body()
        warnings.append(
            "user-data is #include / #include-once style: network fetch "
            "from the container is not yet implemented; skipping"
        )
    else:
        body = _unknown_fallback_body(payload)
        warnings.append(
            "user-data format unrecognised; falling back to /bin/sh "
            "execution (matches real cloud-init's unknown-format behaviour)"
        )

    script = _wrap_with_guard(body, fmt, warnings)
    return TranslatedUserData(fmt, script, warnings)


def classify(payload: bytes) -> UserDataFormat:
    """Detect the user-data format from a (possibly un-gzipped) payload.

    The check order matches cloud-init's: MIME first (because a MIME
    document's first line can be ``Content-Type:`` rather than a
    cloud-init format marker), then the various line-1 markers.
    """
    if not payload:
        return UserDataFormat.EMPTY
    if _looks_like_mime(payload):
        return UserDataFormat.MIME_MULTIPART
    first_line = _first_nonblank_line(payload)
    if first_line.startswith(b"#!"):
        return UserDataFormat.SHEBANG
    if first_line.startswith(b"#cloud-config"):
        return UserDataFormat.CLOUD_CONFIG
    if first_line.startswith(b"#cloud-boothook"):
        return UserDataFormat.CLOUD_BOOTHOOK
    if first_line.startswith(b"#include-once") or first_line.startswith(b"#include"):
        return UserDataFormat.INCLUDE_URL
    return UserDataFormat.UNKNOWN


# ---------------------------------------------------------------------------
# Gzip + MIME helpers
# ---------------------------------------------------------------------------


def _maybe_gunzip(payload: bytes) -> tuple[bytes, bool]:
    if len(payload) >= 2 and payload[0] == 0x1F and payload[1] == 0x8B:
        try:
            return gzip.decompress(payload), True
        except Exception as exc:
            LOG.warning("gzip header present but decompression failed: %s", exc)
    return payload, False


def _looks_like_mime(payload: bytes) -> bool:
    # cloud-init accepts a leading ``Content-Type:`` header even without
    # the ``MIME-Version: 1.0`` line that strict RFC 2822 requires.
    head = payload[:512].lower()
    return b"content-type:" in head and b"multipart/" in head


def _first_nonblank_line(payload: bytes) -> bytes:
    for raw in payload.splitlines():
        line = raw.strip()
        if line:
            return line
    return b""


# ---------------------------------------------------------------------------
# Format bodies
# ---------------------------------------------------------------------------


def _shebang_body(payload: bytes) -> str:
    """Embed a shebang script verbatim, run it once."""
    encoded = base64.b64encode(payload).decode("ascii")
    return _decode_and_run("user-data-shebang.sh", encoded, run_as_script=True)


def _cloud_boothook_body(payload: bytes) -> str:
    """``#cloud-boothook`` runs the same as a shebang for our single-shot
    model. cloud-init runs boothooks on every boot pre-guard, but our
    guard file already protects against re-run on restart so the
    distinction is moot here."""
    # Strip the ``#cloud-boothook`` marker line and use the rest like a
    # shebang script. If the inner body lacks a shebang we add /bin/sh.
    body = _strip_first_line(payload)
    if not body.lstrip().startswith(b"#!"):
        body = b"#!/bin/sh\n" + body
    encoded = base64.b64encode(body).decode("ascii")
    return _decode_and_run("user-data-boothook.sh", encoded, run_as_script=True)


def _include_unsupported_body() -> str:
    return (
        "# #include / #include-once user-data is not yet supported by "
        "LocalEmu (it would require network fetches from inside the "
        "container during boot). Logging and continuing.\n"
        "echo '[localemu-user-data] #include format skipped (not yet implemented)' >&2\n"
    )


def _unknown_fallback_body(payload: bytes) -> str:
    """cloud-init falls back to ``/bin/sh`` for unknown formats. So do we."""
    encoded = base64.b64encode(b"#!/bin/sh\n" + payload).decode("ascii")
    return _decode_and_run("user-data-unknown.sh", encoded, run_as_script=True)


def _decode_and_run(filename: str, b64_payload: str, *, run_as_script: bool) -> str:
    """Generate shell that writes a base64 payload to a file and runs it."""
    safe_name = shlex.quote(f"/var/lib/localemu/{filename}")
    decode_block = (
        f"printf '%s' {shlex.quote(b64_payload)} | base64 -d > {safe_name}\n"
        f"chmod +x {safe_name}\n"
    )
    if run_as_script:
        # Run via the shell so an absent interpreter (e.g. user wrote
        # ``#!/usr/bin/python3`` and the image has no python) still
        # produces a clear "interpreter not found" log line.
        return decode_block + f"{safe_name}\n"
    return decode_block


# ---------------------------------------------------------------------------
# MIME multipart
# ---------------------------------------------------------------------------


_MIME_HANDLERS = {
    "text/x-shellscript": "_part_shellscript",
    "text/cloud-config": "_part_cloud_config",
    "text/cloud-boothook": "_part_cloud_boothook",
    "text/cloud-config-archive": "_part_cloud_config_archive",
}


def _mime_body(payload: bytes, warnings: list[str]) -> str:
    """Walk a MIME multipart user-data document and translate each part."""
    try:
        msg = email.message_from_bytes(payload, policy=email.policy.default)
    except Exception as exc:
        warnings.append(f"MIME parse failed ({exc}); falling back to /bin/sh")
        return _unknown_fallback_body(payload)

    parts: list[str] = []
    idx = 0
    for part in _walk_mime(msg):
        ctype = (part.get_content_type() or "").lower()
        handler = _MIME_HANDLERS.get(ctype)
        if handler is None:
            warnings.append(f"MIME part #{idx}: unsupported Content-Type {ctype!r}; skipping")
            idx += 1
            continue
        body_bytes = _mime_part_bytes(part)
        translated: str
        if handler == "_part_shellscript":
            translated = _shebang_body(_ensure_shebang(body_bytes))
        elif handler == "_part_cloud_config":
            translated = _cloud_config_body(body_bytes, warnings)
        elif handler == "_part_cloud_boothook":
            translated = _cloud_boothook_body(body_bytes)
        elif handler == "_part_cloud_config_archive":
            translated = _cloud_config_archive_body(body_bytes, warnings)
        else:
            translated = ""
        if translated:
            parts.append(f"# ---- MIME part #{idx} ({ctype}) ----\n{translated}")
        idx += 1
    return "\n".join(parts) if parts else "echo '[localemu-user-data] no supported MIME parts' >&2\n"


def _walk_mime(msg):
    if msg.is_multipart():
        for sub in msg.walk():
            if sub is msg or sub.is_multipart():
                continue
            yield sub
    else:
        yield msg


def _mime_part_bytes(part) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is None:
        # Defensive: get_payload(decode=True) returns None for some shapes.
        payload = part.get_payload()
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")
        else:
            payload = b""
    return payload


def _ensure_shebang(body: bytes) -> bytes:
    if body.lstrip().startswith(b"#!"):
        return body
    return b"#!/bin/sh\n" + body


def _cloud_config_archive_body(payload: bytes, warnings: list[str]) -> str:
    """``text/cloud-config-archive`` is a JSON list of MIME-like entries.

    Each entry: ``{"type": "<content-type>", "content": "<inline data>"}``.
    We translate each entry as if it were its own MIME part.
    """
    try:
        items = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        warnings.append(f"cloud-config-archive JSON parse failed ({exc}); skipping")
        return ""
    if not isinstance(items, list):
        warnings.append("cloud-config-archive root was not a JSON list; skipping")
        return ""

    parts: list[str] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            warnings.append(f"cloud-config-archive item #{i} not an object; skipping")
            continue
        ctype = str(item.get("type", "text/cloud-config")).lower()
        content = item.get("content", "")
        body_bytes = content.encode("utf-8") if isinstance(content, str) else b""
        if ctype == "text/x-shellscript":
            parts.append(_shebang_body(_ensure_shebang(body_bytes)))
        elif ctype == "text/cloud-config":
            parts.append(_cloud_config_body(body_bytes, warnings))
        elif ctype == "text/cloud-boothook":
            parts.append(_cloud_boothook_body(body_bytes))
        else:
            warnings.append(f"cloud-config-archive item #{i}: unsupported type {ctype!r}; skipping")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# #cloud-config translation
# ---------------------------------------------------------------------------


# Known directives — anything outside this set is logged and skipped.
_KNOWN_DIRECTIVES = {
    "packages",
    "package_update",
    "package_upgrade",
    "write_files",
    "bootcmd",
    "runcmd",
    "users",
    "ssh_authorized_keys",
    "disable_root",
    "ssh_pwauth",
    "hostname",
    "manage_etc_hosts",
    "final_message",
}


def _cloud_config_body(payload: bytes, warnings: list[str]) -> str:
    """Parse a ``#cloud-config`` YAML document and emit equivalent shell."""
    try:
        import yaml  # PyYAML is already a LocalEmu runtime dep.
    except Exception as exc:
        warnings.append(f"PyYAML not importable ({exc}); cloud-config skipped")
        return ""

    text = payload.decode("utf-8", errors="replace")
    # Strip the ``#cloud-config`` marker line so YAML's parser doesn't
    # see the leading comment (it would just be ignored, but the doc is
    # cleaner without it). cloud-init's loader does the same.
    text = _strip_cloud_config_marker(text)

    try:
        doc = yaml.safe_load(text)
    except Exception as exc:
        warnings.append(f"cloud-config YAML parse failed ({exc}); skipping")
        return ""

    if doc is None:
        warnings.append("cloud-config YAML was empty after marker strip; skipping")
        return ""
    if not isinstance(doc, dict):
        warnings.append(f"cloud-config top-level is not a mapping ({type(doc).__name__}); skipping")
        return ""

    for key in doc:
        if key not in _KNOWN_DIRECTIVES:
            warnings.append(f"cloud-config directive {key!r} not implemented in LocalEmu; skipping")

    out: list[str] = []
    out.append("# ---- #cloud-config (translated) ----")

    if doc.get("hostname"):
        out.append(_emit_hostname(str(doc["hostname"])))

    pkg_update = bool(doc.get("package_update", False))
    pkg_upgrade = bool(doc.get("package_upgrade", False))
    packages = doc.get("packages") or []
    if pkg_update or pkg_upgrade or packages:
        out.append(_emit_packages(pkg_update, pkg_upgrade, packages, warnings))

    write_files = doc.get("write_files") or []
    if write_files:
        out.append(_emit_write_files(write_files, warnings))

    users = doc.get("users") or []
    if users:
        out.append(_emit_users(users, warnings))

    ssh_keys = doc.get("ssh_authorized_keys") or []
    if ssh_keys:
        out.append(_emit_ssh_authorized_keys(ssh_keys))

    if "ssh_pwauth" in doc:
        out.append(_emit_ssh_pwauth(bool(doc["ssh_pwauth"])))
    if doc.get("disable_root"):
        out.append(_emit_disable_root())

    bootcmds = doc.get("bootcmd") or []
    if bootcmds:
        out.append("# bootcmd")
        out.append(_emit_cmd_list(bootcmds))

    runcmds = doc.get("runcmd") or []
    if runcmds:
        out.append("# runcmd")
        out.append(_emit_cmd_list(runcmds))

    if "manage_etc_hosts" in doc:
        out.append(_emit_manage_etc_hosts(doc.get("manage_etc_hosts"), doc.get("hostname")))

    final_msg = doc.get("final_message")
    if final_msg:
        out.append(f"echo {shlex.quote(str(final_msg))}\n")

    return "\n".join(out)


def _strip_cloud_config_marker(text: str) -> str:
    lines = text.splitlines()
    for i, raw in enumerate(lines):
        if raw.strip().startswith("#cloud-config"):
            return "\n".join(lines[i + 1:])
        if raw.strip():
            # First non-blank line wasn't the marker — return doc as-is.
            return text
    return text


def _strip_first_line(payload: bytes) -> bytes:
    nl = payload.find(b"\n")
    if nl < 0:
        return b""
    return payload[nl + 1:]


# ---- directive emitters ----------------------------------------------------


def _emit_hostname(name: str) -> str:
    name_q = shlex.quote(name)
    return (
        f"# hostname\n"
        f"echo {name_q} > /etc/hostname 2>/dev/null || true\n"
        f"command -v hostname >/dev/null 2>&1 && hostname {name_q} || true\n"
    )


def _emit_packages(update: bool, upgrade: bool, packages: list, warnings: list[str]) -> str:
    """Detect the package manager and emit the equivalent install command."""
    names: list[str] = []
    for entry in packages:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, list) and entry:
            # ``[name, version]`` form -> ``name=version`` for apt,
            # ``name-version`` for dnf/yum. We pick the more universally
            # tolerated ``name`` only and warn that the version was lost.
            names.append(str(entry[0]))
            if len(entry) >= 2:
                warnings.append(
                    f"packages: version pinning ({entry[0]!r}={entry[1]!r}) "
                    "is not applied: package-manager-specific version "
                    "syntax differs across apt/dnf/apk"
                )
        else:
            warnings.append(f"packages: unsupported entry shape {entry!r}; skipping")
    names_q = " ".join(shlex.quote(n) for n in names)
    update_sh = "true"
    upgrade_sh = "true"
    install_sh = "true"
    if update or upgrade or names:
        # apt / dnf / yum / apk (zypper not handled — uncommon on AWS AMIs)
        update_sh = (
            "if command -v apt-get >/dev/null 2>&1; then apt-get update -y || true;"
            " elif command -v dnf >/dev/null 2>&1; then dnf -y makecache || true;"
            " elif command -v yum >/dev/null 2>&1; then yum -y makecache || true;"
            " elif command -v apk >/dev/null 2>&1; then apk update || true;"
            " fi"
        )
    if upgrade:
        upgrade_sh = (
            "if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || true;"
            " elif command -v dnf >/dev/null 2>&1; then dnf -y upgrade || true;"
            " elif command -v yum >/dev/null 2>&1; then yum -y update || true;"
            " elif command -v apk >/dev/null 2>&1; then apk upgrade || true;"
            " fi"
        )
    if names:
        install_sh = (
            f"if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y {names_q} || true;"
            f" elif command -v dnf >/dev/null 2>&1; then dnf -y install {names_q} || true;"
            f" elif command -v yum >/dev/null 2>&1; then yum -y install {names_q} || true;"
            f" elif command -v apk >/dev/null 2>&1; then apk add --no-cache {names_q} || true;"
            f" fi"
        )
    return (
        "# package_update / package_upgrade / packages\n"
        + ("" if not (update or upgrade or names) else update_sh + "\n")
        + ("" if not upgrade else upgrade_sh + "\n")
        + ("" if not names else install_sh + "\n")
    )


def _emit_write_files(entries: list, warnings: list[str]) -> str:
    out = ["# write_files"]
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            warnings.append(f"write_files item #{i} is not a mapping; skipping")
            continue
        path = entry.get("path")
        if not path or not isinstance(path, str):
            warnings.append(f"write_files item #{i}: missing/invalid 'path'; skipping")
            continue
        content = entry.get("content", "")
        encoding = (entry.get("encoding") or "").lower()
        append = bool(entry.get("append", False))
        permissions = entry.get("permissions")  # "0640" / "0o640" / 0o640
        owner = entry.get("owner")

        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray)):
            content_bytes = bytes(content)
        else:
            warnings.append(f"write_files item #{i}: content type {type(content).__name__} ; coercing via str()")
            content_bytes = str(content).encode("utf-8")

        if encoding in ("b64", "base64"):
            try:
                content_bytes = base64.b64decode(content_bytes, validate=False)
            except Exception as exc:
                warnings.append(f"write_files item #{i}: base64 decode failed ({exc}); writing raw")
        elif encoding in ("gz", "gzip"):
            try:
                content_bytes = gzip.decompress(content_bytes)
            except Exception as exc:
                warnings.append(f"write_files item #{i}: gzip decompress failed ({exc}); writing raw")
        elif encoding in ("gz+b64", "gzip+base64", "gz+base64"):
            try:
                content_bytes = gzip.decompress(base64.b64decode(content_bytes))
            except Exception as exc:
                warnings.append(f"write_files item #{i}: gz+b64 decode failed ({exc}); writing raw")

        path_q = shlex.quote(path)
        body_b64 = base64.b64encode(content_bytes).decode("ascii")
        redirect = ">>" if append else ">"
        # ``mkdir -p $(dirname ...)`` — quoted manually to avoid shell-injection
        # by deeply weird path characters.
        out.append(f"mkdir -p $(dirname {path_q}) 2>/dev/null || true")
        out.append(f"printf '%s' {shlex.quote(body_b64)} | base64 -d {redirect} {path_q}")
        if permissions is not None:
            perm_s = _normalise_permissions(permissions)
            if perm_s:
                out.append(f"chmod {perm_s} {path_q} 2>/dev/null || true")
        if owner and isinstance(owner, str):
            out.append(f"chown {shlex.quote(owner)} {path_q} 2>/dev/null || true")
    return "\n".join(out) + "\n"


def _normalise_permissions(perm) -> str | None:
    if isinstance(perm, int):
        return f"{perm:o}"
    if isinstance(perm, str):
        s = perm.strip()
        if s.startswith("0o") or s.startswith("0O"):
            s = s[2:]
        # strip leading zeros only if a numeric octal so ``"0644"`` -> ``"644"``
        if s.isdigit() and all(c in "01234567" for c in s):
            return s.lstrip("0") or "0"
        # treat as-is (chmod also accepts symbolic forms like ``u+x``).
        return s
    return None


def _emit_users(users: list, warnings: list[str]) -> str:
    out = ["# users"]
    for i, u in enumerate(users):
        if u == "default":
            # cloud-init's ``default`` keeps the distro default user; we
            # don't mutate it (would be a no-op anyway since the LocalEmu
            # base image already exposes root as primary).
            continue
        if not isinstance(u, dict):
            warnings.append(f"users item #{i} not a mapping (or 'default'); skipping")
            continue
        name = u.get("name")
        if not name or not isinstance(name, str):
            warnings.append(f"users item #{i}: missing 'name'; skipping")
            continue
        name_q = shlex.quote(name)
        shell = u.get("shell") or "/bin/bash"
        homedir = u.get("homedir") or f"/home/{name}"
        no_create_home = bool(u.get("no_create_home", False))
        groups = u.get("groups") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        sudo_spec = u.get("sudo")  # None / False / str / list
        lock_passwd = bool(u.get("lock_passwd", True))
        passwd = u.get("passwd")  # already-hashed
        ssh_keys = u.get("ssh_authorized_keys") or []

        useradd_args = [
            "-m" if not no_create_home else "-M",
            "-s", shell,
            "-d", homedir,
        ]
        if groups:
            useradd_args += ["-G", ",".join(groups)]
        useradd_q = " ".join(shlex.quote(a) for a in useradd_args)
        out.append(
            f"id {name_q} >/dev/null 2>&1 || "
            f"useradd {useradd_q} {name_q} 2>/dev/null || true"
        )
        if isinstance(passwd, str) and passwd:
            out.append(
                f"echo {shlex.quote(f'{name}:{passwd}')} | chpasswd -e 2>/dev/null || true"
            )
        if lock_passwd and not passwd:
            out.append(
                f"command -v passwd >/dev/null 2>&1 && passwd -l {name_q} 2>/dev/null || true"
            )
        if sudo_spec:
            sudo_lines: list[str] = []
            if isinstance(sudo_spec, list):
                for s in sudo_spec:
                    sudo_lines.append(f"{name} {s}")
            else:
                sudo_lines.append(f"{name} {sudo_spec}")
            sudo_text = "\n".join(sudo_lines) + "\n"
            sudo_b64 = base64.b64encode(sudo_text.encode("utf-8")).decode("ascii")
            sudo_path = f"/etc/sudoers.d/{name}"
            sudo_path_q = shlex.quote(sudo_path)
            out.append(f"mkdir -p /etc/sudoers.d 2>/dev/null || true")
            out.append(
                f"printf '%s' {shlex.quote(sudo_b64)} | base64 -d > {sudo_path_q}"
            )
            out.append(f"chmod 0440 {sudo_path_q} 2>/dev/null || true")
        if ssh_keys:
            out.append(_emit_user_ssh_keys(name, homedir, ssh_keys))
    return "\n".join(out) + "\n"


def _emit_user_ssh_keys(name: str, homedir: str, keys: list) -> str:
    auth_path = f"{homedir}/.ssh/authorized_keys"
    auth_path_q = shlex.quote(auth_path)
    home_ssh_q = shlex.quote(f"{homedir}/.ssh")
    keys_text = ""
    for k in keys:
        if isinstance(k, str) and k.strip():
            keys_text += k.rstrip() + "\n"
    keys_b64 = base64.b64encode(keys_text.encode("utf-8")).decode("ascii")
    name_q = shlex.quote(name)
    return (
        f"mkdir -p {home_ssh_q} 2>/dev/null || true\n"
        f"printf '%s' {shlex.quote(keys_b64)} | base64 -d >> {auth_path_q}\n"
        f"chmod 700 {home_ssh_q} 2>/dev/null || true\n"
        f"chmod 600 {auth_path_q} 2>/dev/null || true\n"
        f"chown -R {name_q}:{name_q} {home_ssh_q} 2>/dev/null || true"
    )


def _emit_ssh_authorized_keys(keys: list) -> str:
    """Append keys to root's ``authorized_keys``."""
    keys_text = ""
    for k in keys:
        if isinstance(k, str) and k.strip():
            keys_text += k.rstrip() + "\n"
    keys_b64 = base64.b64encode(keys_text.encode("utf-8")).decode("ascii")
    return (
        "# ssh_authorized_keys (root)\n"
        "mkdir -p /root/.ssh 2>/dev/null || true\n"
        f"printf '%s' {shlex.quote(keys_b64)} | base64 -d >> /root/.ssh/authorized_keys\n"
        "chmod 700 /root/.ssh 2>/dev/null || true\n"
        "chmod 600 /root/.ssh/authorized_keys 2>/dev/null || true\n"
    )


def _emit_ssh_pwauth(allow: bool) -> str:
    value = "yes" if allow else "no"
    return (
        "# ssh_pwauth\n"
        f"if [ -f /etc/ssh/sshd_config ]; then "
        f"sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication {value}/' /etc/ssh/sshd_config; "
        "fi\n"
    )


def _emit_disable_root() -> str:
    return (
        "# disable_root\n"
        "if [ -f /etc/ssh/sshd_config ]; then "
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config; "
        "fi\n"
    )


def _emit_manage_etc_hosts(value, hostname) -> str:
    if not value or not hostname:
        return ""
    name_q = shlex.quote(str(hostname))
    return (
        "# manage_etc_hosts\n"
        f"printf '127.0.0.1 localhost %s\\n::1 localhost %s\\n' "
        f"{name_q} {name_q} > /etc/hosts 2>/dev/null || true\n"
    )


def _emit_cmd_list(cmds: list) -> str:
    lines: list[str] = []
    for entry in cmds:
        if entry is None:
            continue
        if isinstance(entry, str):
            # ``sh -c`` so the user's quoting applies as-is.
            lines.append(f"sh -c {shlex.quote(entry)}")
        elif isinstance(entry, list):
            argv = " ".join(shlex.quote(str(a)) for a in entry)
            lines.append(argv)
        else:
            # cloud-init silently coerces to str — match.
            lines.append(f"sh -c {shlex.quote(str(entry))}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Guard / wrapper
# ---------------------------------------------------------------------------


_GUARD_PATH = "/var/lib/localemu/user-data-ran"
_PROCESS_LOG = "/var/log/cloud-init.log"
_OUTPUT_LOG = "/var/log/cloud-init-output.log"
_LEGACY_LOG = "/var/log/user-data.log"


def _wrap_empty() -> str:
    return (
        "#!/bin/sh\n"
        "# LocalEmu cloud-init: user-data was empty; nothing to do.\n"
        "exit 0\n"
    )


def _wrap_with_guard(body: str, fmt: UserDataFormat, warnings: list[str]) -> str:
    """Wrap a translated body in the guard + log infrastructure.

    The resulting script:
        * exits 0 immediately if the guard file already exists (one-shot).
        * writes the cloud-init standard log paths
          ``/var/log/cloud-init.log`` (process log) and
          ``/var/log/cloud-init-output.log`` (user command output) and
          keeps ``/var/log/user-data.log`` as a symlink alias for
          back-compat with the LocalEmu E2E scripts.
        * touches the guard at the end so subsequent boots no-op.
    """
    fmt_str = fmt.value
    warning_lines = ""
    for w in warnings:
        # Quote each warning safely for inclusion in the heredoc.
        warning_lines += f"echo [localemu-user-data] WARN: {shlex.quote(w)}\n"
    return f"""#!/bin/sh
# LocalEmu cloud-init translator output (format={fmt_str}).
# Re-run is suppressed by the guard file at {_GUARD_PATH}.
set +e

GUARD={shlex.quote(_GUARD_PATH)}
PROCESS_LOG={shlex.quote(_PROCESS_LOG)}
OUTPUT_LOG={shlex.quote(_OUTPUT_LOG)}
LEGACY_LOG={shlex.quote(_LEGACY_LOG)}

if [ -f "$GUARD" ]; then
    exit 0
fi

mkdir -p /var/lib/localemu /var/log 2>/dev/null || true

# cloud-init's process-log goes to PROCESS_LOG (timestamps, status).
# All stdout/stderr of the user's directives goes to OUTPUT_LOG.
# LEGACY_LOG is kept as a symlink alias for older LocalEmu E2E scripts.
ln -sf "$OUTPUT_LOG" "$LEGACY_LOG" 2>/dev/null || true

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] localemu-cloud-init: starting (format={fmt_str})" >> "$PROCESS_LOG"
{warning_lines}

(
{body}
) >> "$OUTPUT_LOG" 2>&1
rc=$?

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] localemu-cloud-init: complete (exit=$rc)" >> "$PROCESS_LOG"
: > "$GUARD"
exit $rc
"""
