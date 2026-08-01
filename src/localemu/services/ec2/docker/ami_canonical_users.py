"""Per-AMI canonical Linux user for SSH key injection.

Real AWS AMIs each ship a distinct default Linux user :

- Ubuntu / LocalEmu-managed AMIs      -> ``ubuntu``
- Amazon Linux 2 / Amazon Linux 2023  -> ``ec2-user``
- Debian 11 / 12                      -> ``admin``
- Alpine                              -> ``alpine``
- CentOS Stream 9                     -> ``cloud-user``

Every ``ssh …@<PublicIpAddress>`` tutorial in the wild uses that
canonical user. Prior to LocalEmu 1.2.0 the base image had only
``root``, so ``--key-name`` at ``run-instances`` combined with
``ssh ubuntu@…`` failed with "Permission denied (publickey)" - the
key was injected into ``/root/.ssh/authorized_keys`` but nobody
tries to SSH as root by default on real AWS.

Resolution order in ``vm_manager._inject_ssh_key`` :

1. Explicit AMI-id → user mapping from ``CANONICAL_USER`` below.
2. Fallback to ``root`` when the AMI has no canonical user (custom
   or unknown AMIs).

The key is written to :

- ``~<canonical_user>/.ssh/authorized_keys`` - the tutorial-standard
  path AWS uses for the AMI's OS convention.
- ``/root/.ssh/authorized_keys`` - matches real Amazon-Linux behaviour
  (root SSH is enabled with the same key as ec2-user for the first
  boot), plus keeps back-compat for callers that still SSH as root.
"""
from __future__ import annotations

# Exact-match table. Keys are AMI IDs the LocalEmu ami_mapping already
# knows about (see ``ami_mapping.py``). Values are the OS's canonical
# Linux user.
CANONICAL_USER: dict[str, str] = {
    # Ubuntu family (LocalEmu-managed base image + upstream mirrors)
    "ami-ubuntu-22.04":     "ubuntu",
    "ami-ubuntu-24.04":     "ubuntu",
    "ami-ubuntu-20.04":     "ubuntu",
    "ami-localemu-ubuntu":  "ubuntu",
    # Amazon Linux
    "ami-amazon-linux-2023": "ec2-user",
    "ami-amazon-linux-2":    "ec2-user",
    "ami-al2023":            "ec2-user",
    # Debian
    "ami-debian-12":         "admin",
    "ami-debian-11":         "admin",
    # Alpine (LocalEmu convention; cloud-init on real AWS Alpine AMIs
    # creates ``alpine`` as the default).
    "ami-alpine-3.20":       "alpine",
    "ami-alpine-3.18":       "alpine",
    # CentOS Stream
    "ami-centos-9":          "cloud-user",
}


def resolve_canonical_user(ami_id: str | None) -> str | None:
    """Return the AMI's canonical Linux user, or ``None`` when the
    AMI is unknown.

    ``None`` is a legitimate signal to callers : "no LocalEmu-known
    user for this AMI, fall back to root and log INFO". Prefer
    returning ``None`` over guessing ``ubuntu`` for a custom AMI whose
    convention we do not know.
    """
    if not ami_id:
        return None
    return CANONICAL_USER.get(ami_id)
