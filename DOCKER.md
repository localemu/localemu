<p align="center">
  <strong>LocalEmu</strong> - A free, open-source cloud service emulator.
</p>

<p align="center">
  <a href="https://github.com/localemu/localemu/actions"><img alt="GitHub Actions" src="https://github.com/localemu/localemu/actions/workflows/aws-main.yml/badge.svg?branch=main"></a>
  <a href="https://pypi.org/project/localemu/"><img alt="PyPI Version" src="https://img.shields.io/pypi/v/localemu?color=blue"></a>
  <a href="https://hub.docker.com/r/localemu/localemu"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/localemu/localemu"></a>
  <a href="https://img.shields.io/pypi/l/localemu.svg"><img alt="PyPI License" src="https://img.shields.io/pypi/l/localemu.svg"></a>
  <a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
  <a href="https://github.com/astral-sh/ruff"><img alt="Ruff" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json"></a>
</p>

# What is LocalEmu?

[LocalEmu](https://localemu.cloud) is a free, open-source cloud service emulator that runs in a single container on your laptop or in your CI environment. With LocalEmu, you can run your AWS applications or Lambdas entirely on your local machine without connecting to a remote cloud provider.

No account, no authentication token, no sign-up required. Ever.

LocalEmu supports a growing number of AWS services, like AWS Lambda, S3, DynamoDB, Kinesis, SQS, SNS, and many more! You can find a comprehensive list of supported APIs on our [Feature Coverage](https://localemu.cloud/docs/services) page.

## Usage

Please make sure that you have a working [Docker environment](https://docs.docker.com/get-docker/) on your machine before moving on. You can check if Docker is correctly configured on your machine by executing `docker info` in your terminal.

### Docker CLI

You can directly start the LocalEmu container using the Docker CLI:

```console
$ docker run --rm -it -p 4566:4566 -p 4510-4559:4510-4559 localemu/localemu
```

Create an S3 bucket with the `awsemu` CLI:

```
$ awsemu s3api create-bucket --bucket sample-bucket
$ awsemu s3api list-buckets
```

**Notes**

- This command reuses the image if it's already on your machine, i.e. it will **not** pull the latest image automatically from Docker Hub.

- This command does not bind all ports that are potentially used by LocalEmu, nor does it mount any volumes. When using Docker to manually start LocalEmu, you will have to configure the container on your own (see [`docker-compose.yml`](https://github.com/localemu/localemu/blob/main/docker-compose.yml) and [Configuration](https://localemu.cloud/docs/configuration)).

### Docker Compose

You can start LocalEmu with [Docker Compose](https://docs.docker.com/compose/) by configuring a `docker-compose.yml` file:

```yaml
services:
  localemu:
    container_name: "${LOCALEMU_DOCKER_NAME:-localemu-main}"
    image: localemu/localemu
    ports:
      - "127.0.0.1:4566:4566"            # LocalEmu Gateway
      - "127.0.0.1:4510-4559:4510-4559"  # external services port range
    environment:
      # LocalEmu configuration: https://localemu.cloud/docs/configuration
      - DEBUG=${DEBUG:-0}
    volumes:
      - "${LOCALEMU_VOLUME_DIR:-./volume}:/var/lib/localemu"
      - "/var/run/docker.sock:/var/run/docker.sock"
```

Start the container by running:

```console
$ docker-compose up
```

## Base Image Tags

We push a set of different image tags for the LocalEmu Docker images:

- `latest` (default)
  - Refers to the latest commit which has been fully tested.
  - This tag can contain breaking changes.
- `stable`
  - Refers to the latest tagged release.
- `<major>` (e.g. `1`)
  - Latest release of a specific major version.
- `<major>.<minor>` (e.g. `1.0`)
  - Latest release of a specific minor version.
- `<major>.<minor>.<patch>` (e.g. `1.0.0`)
  - A specific release. Will not be updated.

## Where to get help

- [LocalEmu GitHub Issues](https://github.com/localemu/localemu/issues)
- [LocalEmu Discussions](https://github.com/localemu/localemu/discussions)
- [LocalEmu Documentation](https://localemu.cloud/docs)

## License

Copyright (c) 2026 TocConsulting and LocalEmu contributors.

Copyright (c) 2017-2026 LocalStack contributors.

Copyright (c) 2016 Atlassian and others.

This version of LocalEmu is released under the Apache License, Version 2.0 (see [LICENSE](https://github.com/localemu/localemu/blob/main/LICENSE) and [NOTICE](https://github.com/localemu/localemu/blob/main/NOTICE)).
