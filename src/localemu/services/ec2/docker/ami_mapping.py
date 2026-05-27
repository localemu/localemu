"""AMI to Docker image mapping for EC2 Docker backend.

Maps AMI IDs and names to Docker images. Users can register custom AMIs
by tagging Docker images with the localemu-ec2 prefix.

The default and the ``ami-ubuntu-22.04`` entry both resolve to the
LocalEmu-managed base image (``localemu/ec2-base:latest``) which has
openssh, iptables and net tooling pre-installed. Without that, EC2
containers on internal VPC networks cannot reach package mirrors at
runtime and silently exit.
"""

import logging

from localemu.utils.docker_utils import DOCKER_CLIENT

from .base_image import BASE_IMAGE_TAG

LOG = logging.getLogger(__name__)

# Built-in AMI ID to Docker image mapping
# These are pseudo-AMI IDs that map to well-known Docker images
BUILTIN_AMI_MAP: dict[str, str] = {
    # LocalEmu-managed Ubuntu base — has sshd + iptables + curl pre-baked
    "ami-ubuntu-22.04": BASE_IMAGE_TAG,
    "ami-localemu-ubuntu": BASE_IMAGE_TAG,
    # Amazon Linux
    "ami-amazon-linux-2023": "amazonlinux:2023",
    "ami-amazon-linux-2": "amazonlinux:2",
    "ami-al2023": "amazonlinux:2023",
    # Ubuntu (other versions — bare upstream images, no LocalEmu tooling)
    "ami-ubuntu-24.04": "ubuntu:24.04",
    "ami-ubuntu-20.04": "ubuntu:20.04",
    # Debian
    "ami-debian-12": "debian:12",
    "ami-debian-11": "debian:11",
    # Alpine
    "ami-alpine-3.20": "alpine:3.20",
    "ami-alpine-3.18": "alpine:3.18",
    # CentOS
    "ami-centos-9": "quay.io/centos/centos:stream9",
}

DEFAULT_IMAGE = BASE_IMAGE_TAG


def resolve_ami_to_image(ami_id: str, ami_name: str | None = None) -> str:
    """Resolve an AMI ID to a Docker image name.

    Resolution order:
    1. Check built-in AMI ID mapping
    2. Check if ami_name matches a built-in key
    3. Check for a Docker image tagged as localemu-ec2/<ami-id>
    4. Fall back to DEFAULT_IMAGE

    Args:
        ami_id: The AMI ID (e.g., ami-ubuntu-22.04 or ami-0abc123)
        ami_name: Optional AMI name for fuzzy matching

    Returns:
        Docker image name (e.g., ubuntu:22.04)
    """
    # 1. Direct AMI ID match
    if ami_id in BUILTIN_AMI_MAP:
        image = BUILTIN_AMI_MAP[ami_id]
        LOG.debug("AMI %s resolved to built-in image %s", ami_id, image)
        return image

    # 2. Match by AMI name
    if ami_name:
        name_lower = ami_name.lower()
        for key, image in BUILTIN_AMI_MAP.items():
            if key.replace("ami-", "") in name_lower:
                LOG.debug("AMI %s (name=%s) resolved to %s", ami_id, ami_name, image)
                return image

    # 3. Check for custom tagged image. pull=False is load-bearing: the
    # default inspect_image() tries to pull on miss, which for unknown
    # AMI IDs produces a "pull access denied" stderr write against a
    # public-registry path (e.g. localemu-ec2/ami-localemu) that never
    # existed. We just want to know whether the user has tagged a local
    # image with this prefix; if not, fall through to DEFAULT_IMAGE.
    custom_image = f"localemu-ec2/{ami_id}"
    try:
        DOCKER_CLIENT.inspect_image(custom_image, pull=False)
        LOG.debug("AMI %s resolved to custom image %s", ami_id, custom_image)
        return custom_image
    except Exception:
        pass

    # 4. Fall back to default
    LOG.info("AMI %s has no mapping, using default image %s", ami_id, DEFAULT_IMAGE)
    return DEFAULT_IMAGE


# Instance type to resource limits mapping
INSTANCE_TYPE_RESOURCES: dict[str, dict] = {
    "t2.nano":    {"mem_limit": "512m", "cpu_shares": 128},
    "t2.micro":   {"mem_limit": "1g",   "cpu_shares": 256},
    "t2.small":   {"mem_limit": "2g",   "cpu_shares": 512},
    "t2.medium":  {"mem_limit": "4g",   "cpu_shares": 1024},
    "t2.large":   {"mem_limit": "8g",   "cpu_shares": 2048},
    "t3.nano":    {"mem_limit": "512m", "cpu_shares": 128},
    "t3.micro":   {"mem_limit": "1g",   "cpu_shares": 256},
    "t3.small":   {"mem_limit": "2g",   "cpu_shares": 512},
    "t3.medium":  {"mem_limit": "4g",   "cpu_shares": 1024},
    "t3.large":   {"mem_limit": "8g",   "cpu_shares": 2048},
    "m5.large":   {"mem_limit": "8g",   "cpu_shares": 2048},
    "m5.xlarge":  {"mem_limit": "16g",  "cpu_shares": 4096},
}

DEFAULT_RESOURCES = {"mem_limit": "1g", "cpu_shares": 256}


def get_instance_resources(instance_type: str) -> dict:
    """Get resource limits for an instance type.

    Args:
        instance_type: EC2 instance type (e.g., t2.micro)

    Returns:
        Dict with mem_limit and cpu_shares
    """
    return INSTANCE_TYPE_RESOURCES.get(instance_type, DEFAULT_RESOURCES)
