"""Unit tests for ``localemu.services.ec2.docker.user_data``.

Pin the cloud-init user-data translator end-to-end:
classification, gzip auto-detection, every supported #cloud-config
directive, MIME multipart walking, guard file + log path emission.

These tests run against the pure-Python translator (no Docker), so
they exercise the full surface in milliseconds.
"""
from __future__ import annotations

import base64
import gzip
import json
import re
import textwrap

import pytest

from localemu.services.ec2.docker.user_data import (
    TranslatedUserData,
    UserDataFormat,
    build_cloud_init_shell,
    classify,
)


# ---------------------------------------------------------------------------
# classify()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload, expected",
    [
        (b"", UserDataFormat.EMPTY),
        (b"#!/bin/bash\necho hi\n", UserDataFormat.SHEBANG),
        (b"   #!/bin/sh\nwhoami\n", UserDataFormat.SHEBANG),
        (b"#cloud-config\nruncmd: [ls]\n", UserDataFormat.CLOUD_CONFIG),
        (b"#cloud-boothook\necho early\n", UserDataFormat.CLOUD_BOOTHOOK),
        (b"#include\nhttp://example.com/script\n", UserDataFormat.INCLUDE_URL),
        (b"#include-once\nhttp://example.com/script\n", UserDataFormat.INCLUDE_URL),
        (b"Content-Type: multipart/mixed; boundary=BNDRY\n\n--BNDRY--", UserDataFormat.MIME_MULTIPART),
        (b"random bytes that are not cloud-init", UserDataFormat.UNKNOWN),
    ],
)
def test_classify(payload, expected):
    assert classify(payload) is expected


def test_classify_skips_blank_lines_before_marker():
    payload = b"\n\n   \n#cloud-config\nruncmd: [whoami]\n"
    assert classify(payload) is UserDataFormat.CLOUD_CONFIG


# ---------------------------------------------------------------------------
# Guard / wrapper invariants — every translation honours the contract
# ---------------------------------------------------------------------------


def _assert_guarded_script(result: TranslatedUserData) -> str:
    script = result.shell_script
    assert script.startswith("#!/bin/sh\n"), "scripts must declare /bin/sh"
    if result.format is UserDataFormat.EMPTY:
        return script
    assert "GUARD=" in script, "guard variable must be declared"
    assert "/var/lib/localemu/user-data-ran" in script, "guard path must match the contract"
    assert "/var/log/cloud-init.log" in script, "cloud-init process log path missing"
    assert "/var/log/cloud-init-output.log" in script, "cloud-init output log path missing"
    assert "/var/log/user-data.log" in script, "legacy log path alias missing"
    assert "exit 0" in script, "guard must short-circuit subsequent boots"
    assert ': > "$GUARD"' in script, "guard file must be touched at the end"
    return script


# ---------------------------------------------------------------------------
# Shebang scripts
# ---------------------------------------------------------------------------


def test_shebang_script_is_embedded_base64():
    payload = b"#!/bin/bash\necho PWNED > /tmp/pwned_marker\n"
    result = build_cloud_init_shell(payload)
    assert result.format is UserDataFormat.SHEBANG
    script = _assert_guarded_script(result)
    encoded = base64.b64encode(payload).decode("ascii")
    assert encoded in script, "shebang body must be embedded as base64"
    assert "/var/lib/localemu/user-data-shebang.sh" in script
    assert "base64 -d" in script
    assert "chmod +x" in script


def test_empty_user_data_yields_noop_script():
    result = build_cloud_init_shell(None)
    assert result.format is UserDataFormat.EMPTY
    assert result.shell_script.strip().endswith("exit 0")
    result = build_cloud_init_shell(b"")
    assert result.format is UserDataFormat.EMPTY


# ---------------------------------------------------------------------------
# gzip auto-detection
# ---------------------------------------------------------------------------


def test_gzip_wrapped_shebang_is_decompressed_and_classified():
    inner = b"#!/bin/sh\necho gz-ran > /tmp/g\n"
    payload = gzip.compress(inner)
    assert payload[:2] == b"\x1f\x8b"
    result = build_cloud_init_shell(payload)
    assert result.format is UserDataFormat.SHEBANG
    encoded_inner = base64.b64encode(inner).decode("ascii")
    assert encoded_inner in result.shell_script


def test_gzip_wrapped_cloud_config_is_classified_after_decompress():
    inner = b"#cloud-config\nruncmd:\n  - touch /tmp/gz-cc\n"
    payload = gzip.compress(inner)
    result = build_cloud_init_shell(payload)
    assert result.format is UserDataFormat.CLOUD_CONFIG
    assert "sh -c 'touch /tmp/gz-cc'" in result.shell_script


# ---------------------------------------------------------------------------
# #cloud-config: runcmd / bootcmd
# ---------------------------------------------------------------------------


def test_runcmd_string_uses_sh_dash_c():
    payload = b"#cloud-config\nruncmd:\n  - echo hi > /tmp/r\n"
    script = build_cloud_init_shell(payload).shell_script
    assert "sh -c 'echo hi > /tmp/r'" in script


def test_runcmd_list_uses_argv_directly():
    payload = b"#cloud-config\nruncmd:\n  - [ /usr/bin/touch, /tmp/argv ]\n"
    script = build_cloud_init_shell(payload).shell_script
    assert "/usr/bin/touch /tmp/argv" in script
    # Must not be wrapped in ``sh -c`` for the list form.
    assert "sh -c '/usr/bin/touch /tmp/argv'" not in script


def test_bootcmd_is_emitted_before_runcmd():
    payload = textwrap.dedent("""\
        #cloud-config
        bootcmd:
          - echo boot > /tmp/b
        runcmd:
          - echo run > /tmp/r
    """).encode()
    script = build_cloud_init_shell(payload).shell_script
    boot_idx = script.index("# bootcmd")
    run_idx = script.index("# runcmd")
    assert boot_idx < run_idx
    assert "sh -c 'echo boot > /tmp/b'" in script
    assert "sh -c 'echo run > /tmp/r'" in script


# ---------------------------------------------------------------------------
# #cloud-config: write_files
# ---------------------------------------------------------------------------


def test_write_files_plain_content():
    payload = textwrap.dedent("""\
        #cloud-config
        write_files:
          - path: /etc/motd
            content: |
              welcome to localemu
            permissions: '0644'
            owner: root:root
    """).encode()
    script = build_cloud_init_shell(payload).shell_script
    assert "mkdir -p $(dirname /etc/motd)" in script
    expected_b64 = base64.b64encode(b"welcome to localemu\n").decode("ascii")
    assert expected_b64 in script
    assert "chmod 644 /etc/motd" in script
    assert "chown root:root /etc/motd" in script


def test_write_files_b64_encoding_is_decoded_at_translation_time():
    raw = b"\x00\x01binary\nblob"
    encoded = base64.b64encode(raw).decode("ascii")
    payload = (
        b"#cloud-config\n"
        b"write_files:\n"
        b"  - path: /tmp/raw\n"
        b"    encoding: b64\n"
        b"    content: " + encoded.encode() + b"\n"
    )
    script = build_cloud_init_shell(payload).shell_script
    # The script writes the raw bytes (re-encoded as base64 for the heredoc).
    re_encoded = base64.b64encode(raw).decode("ascii")
    assert re_encoded in script


def test_write_files_append_uses_double_redirect():
    payload = textwrap.dedent("""\
        #cloud-config
        write_files:
          - path: /etc/profile
            content: 'export FOO=bar'
            append: true
    """).encode()
    script = build_cloud_init_shell(payload).shell_script
    assert ">> /etc/profile" in script
    assert " > /etc/profile" not in script


def test_write_files_integer_permissions_normalised():
    payload = textwrap.dedent("""\
        #cloud-config
        write_files:
          - path: /tmp/p
            content: 'x'
            permissions: 0o600
    """).encode()
    script = build_cloud_init_shell(payload).shell_script
    assert "chmod 600 /tmp/p" in script


# ---------------------------------------------------------------------------
# #cloud-config: packages
# ---------------------------------------------------------------------------


def test_packages_emits_multi_distro_branches():
    payload = textwrap.dedent("""\
        #cloud-config
        package_update: true
        packages:
          - curl
          - htop
    """).encode()
    script = build_cloud_init_shell(payload).shell_script
    assert "apt-get install -y curl htop" in script
    assert "dnf -y install curl htop" in script
    assert "yum -y install curl htop" in script
    assert "apk add --no-cache curl htop" in script


def test_packages_with_version_pair_drops_version_with_warning():
    payload = textwrap.dedent("""\
        #cloud-config
        packages:
          - [curl, '7.81.0']
    """).encode()
    result = build_cloud_init_shell(payload)
    assert any("version pinning" in w for w in result.warnings)
    assert "apt-get install -y curl" in result.shell_script


# ---------------------------------------------------------------------------
# #cloud-config: users + ssh keys + sshd toggles
# ---------------------------------------------------------------------------


def test_users_minimal_useradd_and_sudoers():
    payload = textwrap.dedent("""\
        #cloud-config
        users:
          - default
          - name: alice
            shell: /bin/bash
            groups: [wheel, docker]
            sudo: ALL=(ALL) NOPASSWD:ALL
            ssh_authorized_keys:
              - ssh-rsa AAAAB3Nz alice@home
    """).encode()
    script = build_cloud_init_shell(payload).shell_script
    assert "id alice >/dev/null 2>&1 || useradd" in script
    assert "-G wheel,docker" in script
    # Sudoers file path
    assert "/etc/sudoers.d/alice" in script
    # ssh key heredoc
    key_b64 = base64.b64encode(b"ssh-rsa AAAAB3Nz alice@home\n").decode("ascii")
    assert key_b64 in script
    assert "/home/alice/.ssh/authorized_keys" in script
    assert "chmod 700 /home/alice/.ssh" in script
    assert "chown -R alice:alice /home/alice/.ssh" in script


def test_users_default_keyword_is_a_noop():
    payload = b"#cloud-config\nusers:\n  - default\n"
    script = build_cloud_init_shell(payload).shell_script
    # No useradd line because only ``default`` was given.
    assert "useradd" not in script


def test_ssh_authorized_keys_top_level_appends_to_root():
    payload = textwrap.dedent("""\
        #cloud-config
        ssh_authorized_keys:
          - ssh-rsa AAAA root-key
    """).encode()
    script = build_cloud_init_shell(payload).shell_script
    assert "/root/.ssh/authorized_keys" in script
    key_b64 = base64.b64encode(b"ssh-rsa AAAA root-key\n").decode("ascii")
    assert key_b64 in script


def test_ssh_pwauth_true_toggles_password_auth_on():
    payload = b"#cloud-config\nssh_pwauth: true\n"
    script = build_cloud_init_shell(payload).shell_script
    assert "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/'" in script


def test_ssh_pwauth_false_toggles_password_auth_off():
    payload = b"#cloud-config\nssh_pwauth: false\n"
    script = build_cloud_init_shell(payload).shell_script
    assert "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/'" in script


def test_disable_root_rewrites_permitrootlogin_no():
    payload = b"#cloud-config\ndisable_root: true\n"
    script = build_cloud_init_shell(payload).shell_script
    assert "PermitRootLogin no" in script


# ---------------------------------------------------------------------------
# #cloud-config: hostname / manage_etc_hosts / final_message
# ---------------------------------------------------------------------------


def test_hostname_directive_writes_etc_hostname():
    payload = b"#cloud-config\nhostname: webhead-01\n"
    script = build_cloud_init_shell(payload).shell_script
    assert "echo webhead-01 > /etc/hostname" in script
    assert "hostname webhead-01" in script


def test_manage_etc_hosts_with_hostname_emits_hosts_file():
    payload = b"#cloud-config\nhostname: api-01\nmanage_etc_hosts: true\n"
    script = build_cloud_init_shell(payload).shell_script
    assert "127.0.0.1 localhost %s" in script
    assert "api-01" in script


def test_final_message_is_printed_to_output_log():
    payload = b"#cloud-config\nfinal_message: 'boot complete'\n"
    script = build_cloud_init_shell(payload).shell_script
    assert "echo 'boot complete'" in script


# ---------------------------------------------------------------------------
# Warnings for unknown directives + malformed input
# ---------------------------------------------------------------------------


def test_unknown_directive_logs_warning_but_translates_known_ones():
    payload = textwrap.dedent("""\
        #cloud-config
        runcmd:
          - touch /tmp/known
        unknown_directive_alpha: 42
        another_unknown:
          nested: yes
    """).encode()
    result = build_cloud_init_shell(payload)
    assert any("unknown_directive_alpha" in w for w in result.warnings)
    assert any("another_unknown" in w for w in result.warnings)
    assert "touch /tmp/known" in result.shell_script


def test_invalid_yaml_logs_warning_and_skips():
    payload = b"#cloud-config\n: : : : not valid yaml\n"
    result = build_cloud_init_shell(payload)
    assert any("YAML parse failed" in w for w in result.warnings)
    # Still produces a guarded script (empty body inside the wrapper).
    _assert_guarded_script(result)


def test_non_dict_top_level_yaml_logs_warning():
    payload = b"#cloud-config\n- just a list\n- not a map\n"
    result = build_cloud_init_shell(payload)
    assert any("not a mapping" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# MIME multipart
# ---------------------------------------------------------------------------


def _build_mime(parts: list[tuple[str, str]]) -> bytes:
    """Build a minimal multipart/mixed user-data blob.

    ``parts`` is a list of ``(content_type, body)`` tuples.
    """
    boundary = "BNDRY"
    out = [
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"",
        "MIME-Version: 1.0",
        "",
    ]
    for ctype, body in parts:
        out.append(f"--{boundary}")
        out.append(f"Content-Type: {ctype}")
        out.append("")
        out.append(body)
    out.append(f"--{boundary}--")
    return "\n".join(out).encode("utf-8")


def test_mime_walks_parts_and_translates_each():
    blob = _build_mime([
        ("text/x-shellscript", "#!/bin/sh\necho s > /tmp/s\n"),
        ("text/cloud-config", "runcmd:\n  - touch /tmp/cc\n"),
    ])
    result = build_cloud_init_shell(blob)
    assert result.format is UserDataFormat.MIME_MULTIPART
    script = result.shell_script
    assert "/var/lib/localemu/user-data-shebang.sh" in script
    assert "sh -c 'touch /tmp/cc'" in script


def test_mime_unsupported_part_is_warned_and_skipped():
    blob = _build_mime([
        ("text/cloud-config", "runcmd:\n  - touch /tmp/cc\n"),
        ("text/upstart-job", "description 'foo'\n"),  # obsolete
    ])
    result = build_cloud_init_shell(blob)
    assert any("upstart-job" in w for w in result.warnings)
    assert "touch /tmp/cc" in result.shell_script


def test_mime_cloud_config_archive_recurses():
    archive = json.dumps([
        {"type": "text/x-shellscript", "content": "#!/bin/sh\necho a\n"},
        {"type": "text/cloud-config", "content": "runcmd:\n  - touch /tmp/arch\n"},
    ])
    blob = _build_mime([("text/cloud-config-archive", archive)])
    result = build_cloud_init_shell(blob)
    assert "/var/lib/localemu/user-data-shebang.sh" in result.shell_script
    assert "touch /tmp/arch" in result.shell_script


# ---------------------------------------------------------------------------
# #cloud-boothook + unknown fallback
# ---------------------------------------------------------------------------


def test_cloud_boothook_runs_as_shell_script():
    payload = b"#cloud-boothook\necho bh > /tmp/bh\n"
    result = build_cloud_init_shell(payload)
    assert result.format is UserDataFormat.CLOUD_BOOTHOOK
    assert "user-data-boothook.sh" in result.shell_script


def test_unknown_format_falls_back_to_bin_sh_with_warning():
    payload = b"this is not any known cloud-init format\necho fallback\n"
    result = build_cloud_init_shell(payload)
    assert result.format is UserDataFormat.UNKNOWN
    assert any("unrecognised" in w for w in result.warnings)
    assert "user-data-unknown.sh" in result.shell_script


def test_include_url_format_is_logged_and_skipped():
    payload = b"#include\nhttp://example.com/script.sh\n"
    result = build_cloud_init_shell(payload)
    assert result.format is UserDataFormat.INCLUDE_URL
    assert any("not yet implemented" in w for w in result.warnings)
    # Guarded wrapper is still produced (no-op body).
    _assert_guarded_script(result)


# ---------------------------------------------------------------------------
# Guard / log invariants (apply to every non-empty translation)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        b"#!/bin/sh\necho hi\n",
        b"#cloud-config\nruncmd: [whoami]\n",
        b"#cloud-boothook\necho hi\n",
        b"random unknown bytes",
    ],
)
def test_every_format_produces_a_guarded_script(payload):
    result = build_cloud_init_shell(payload)
    _assert_guarded_script(result)
    # And the body must be inside the ``(...)`` subshell that's redirected
    # to the OUTPUT_LOG — verify by structural shape.
    assert re.search(r"\(\n(.|\n)+?\n\) >> \"\$OUTPUT_LOG\" 2>&1\n", result.shell_script)
