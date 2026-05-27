# Service-backend E2E scripts

Run-once scripts that exercise the 5 service backends shipped in
this session against a **live LocalEmu** process. They are NOT pytest
tests because they spin up real Docker containers and take seconds
to minutes; treat them as smoke tests for the Docker-backed paths.

## Prerequisites

```bash
pip install -e ".[test]"           # installs pika + kafka-python
docker info                        # MQ + Kafka tests need a daemon
```

## Run

Each script wants LocalEmu running with the matching opt-in flag:

```bash
# Scheduler: no opt-in flag needed, but HOSTNAME_FROM_LAMBDA helps
# the spawned Lambda reach LocalEmu when running on macOS.
HOSTNAME_FROM_LAMBDA=host.docker.internal localemu start
python tests/e2e/service_backends/test_scheduler_dispatch_live.py

# Pipes: same hostname env as Scheduler so Lambda can call back.
HOSTNAME_FROM_LAMBDA=host.docker.internal localemu start
python tests/e2e/service_backends/test_pipes_dispatch_live.py

# SESv2: no flag; talks to LocalEmu directly, no Lambda involved.
localemu start
python tests/e2e/service_backends/test_sesv2_mailbox_live.py

# MQ: opt-in flag pulls the ~250 MB rabbitmq:3.13-management image.
MQ_DOCKER_BACKEND=1 localemu start
python tests/e2e/service_backends/test_mq_rabbitmq_live.py

# Kafka (MSK): opt-in flag pulls the ~600 MB apache/kafka:3.7.1 image.
MSK_DOCKER_BACKEND=1 localemu start
python tests/e2e/service_backends/test_kafka_msk_live.py
```

Each script exits 0 on PASS and prints a single-line summary. They
clean up after themselves (delete the schedule / pipe / broker
container they created) so they're safe to re-run back-to-back.
