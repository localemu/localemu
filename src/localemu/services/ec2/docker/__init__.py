"""Docker-backed EC2 instances for LocalEmu.

When EC2_VM_MANAGER=docker is set, RunInstances creates real Docker containers
that users can SSH into, run user data scripts, and access via IMDS.
"""
