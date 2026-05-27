"""RDS engine to Docker image mapping.

Maps RDS engine names and versions to Docker images that provide
the actual database server.
"""

import logging

LOG = logging.getLogger(__name__)

# Engine name -> Docker image mapping
# Format: (engine, version_prefix) -> image
ENGINE_IMAGE_MAP: dict[str, dict[str, str]] = {
    "mysql": {
        "8.4": "mysql:8.4",
        "8.4.3": "mysql:8.4.3",
        "8.4.2": "mysql:8.4.2",
        "8.0": "mysql:8.0",
        "8.0.39": "mysql:8.0.39",
        "8.0.36": "mysql:8.0.36",
        "8.0.35": "mysql:8.0.35",
        "8.0.33": "mysql:8.0.33",
        "5.7": "mysql:5.7",
        "5.7.44": "mysql:5.7.44",
        "default": "mysql:8.0",
    },
    "postgres": {
        "17": "postgres:17",
        "17.2": "postgres:17.2",
        "17.1": "postgres:17.1",
        "16": "postgres:16",
        "16.6": "postgres:16.6",
        "16.4": "postgres:16.4",
        "16.3": "postgres:16.3",
        "15": "postgres:15",
        "15.10": "postgres:15.10",
        "15.8": "postgres:15.8",
        "14": "postgres:14",
        "14.15": "postgres:14.15",
        "14.13": "postgres:14.13",
        "13": "postgres:13",
        "13.18": "postgres:13.18",
        "13.16": "postgres:13.16",
        "default": "postgres:16",
    },
    "mariadb": {
        "11.4": "mariadb:11.4",
        "11.4.4": "mariadb:11.4.4",
        "11.4.3": "mariadb:11.4.3",
        "10.11": "mariadb:10.11",
        "10.11.10": "mariadb:10.11.10",
        "10.11.9": "mariadb:10.11.9",
        "10.6": "mariadb:10.6",
        "10.6.21": "mariadb:10.6.21",
        "10.6.19": "mariadb:10.6.19",
        "default": "mariadb:11.4",
    },
    # Aurora maps to MySQL or PostgreSQL
    "aurora-mysql": {
        "3.08.0": "mysql:8.0.36",
        "3.07.1": "mysql:8.0.36",
        "3.04.0": "mysql:8.0.28",
        "default": "mysql:8.0",
    },
    "aurora-postgresql": {
        "16.4": "postgres:16.4",
        "16.1": "postgres:16",
        "15.8": "postgres:15.8",
        "15.4": "postgres:15",
        "14.13": "postgres:14.13",
        "default": "postgres:16",
    },
}

# Supported engine names (for validation and warnings)
SUPPORTED_ENGINES = set(ENGINE_IMAGE_MAP.keys())

# Default ports for each engine
ENGINE_DEFAULT_PORT: dict[str, int] = {
    "mysql": 3306,
    "postgres": 5432,
    "mariadb": 3306,
    "aurora-mysql": 3306,
    "aurora-postgresql": 5432,
}

# Environment variables for each engine to set credentials
ENGINE_ENV_VARS: dict[str, dict[str, str]] = {
    "mysql": {
        "user_env": "MYSQL_USER",
        "password_env": "MYSQL_PASSWORD",
        "database_env": "MYSQL_DATABASE",
        "root_password_env": "MYSQL_ROOT_PASSWORD",
    },
    "postgres": {
        "user_env": "POSTGRES_USER",
        "password_env": "POSTGRES_PASSWORD",
        "database_env": "POSTGRES_DB",
    },
    "mariadb": {
        "user_env": "MARIADB_USER",
        "password_env": "MARIADB_PASSWORD",
        "database_env": "MARIADB_DATABASE",
        "root_password_env": "MARIADB_ROOT_PASSWORD",
    },
}


def resolve_engine_image(engine: str, engine_version: str | None = None) -> str:
    """Resolve an RDS engine name and version to a Docker image.

    Args:
        engine: RDS engine name (mysql, postgres, mariadb, aurora-mysql, aurora-postgresql)
        engine_version: Optional version string (8.0.36, 16.4, etc.)

    Returns:
        Docker image name (e.g., mysql:8.0.36, postgres:16.4)
    """
    engine_lower = engine.lower()
    versions = ENGINE_IMAGE_MAP.get(engine_lower)

    if not versions:
        LOG.warning(
            "Unsupported RDS engine '%s' — not in %s. "
            "Falling back to postgres:16. Behavior may differ from AWS.",
            engine,
            sorted(SUPPORTED_ENGINES),
        )
        return "postgres:16"

    if engine_version:
        # Try exact match first (e.g., "8.0.36")
        if engine_version in versions:
            return versions[engine_version]
        # Try major.minor match (e.g., "8.0" from "8.0.36")
        parts = engine_version.split(".")
        if len(parts) >= 2:
            major_minor = f"{parts[0]}.{parts[1]}"
            if major_minor in versions:
                LOG.info(
                    "Exact version %s not mapped for %s, using %s",
                    engine_version, engine, major_minor,
                )
                return versions[major_minor]
        # Try major version match (e.g., "16" from "16.4")
        major = parts[0]
        if major in versions:
            LOG.info(
                "Exact version %s not mapped for %s, using major version %s",
                engine_version, engine, major,
            )
            return versions[major]
        LOG.warning(
            "Engine version %s not mapped for %s. Using default image %s.",
            engine_version, engine, versions["default"],
        )

    return versions["default"]


def get_engine_port(engine: str) -> int:
    """Get the default port for an engine."""
    return ENGINE_DEFAULT_PORT.get(engine.lower(), 5432)


def get_engine_env_vars(
    engine: str,
    master_username: str,
    master_password: str,
    db_name: str | None = None,
) -> dict[str, str]:
    """Build environment variables for the database container.

    Args:
        engine: RDS engine name
        master_username: Master username
        master_password: Master password
        db_name: Optional database name to create

    Returns:
        Dict of environment variables for the Docker container
    """
    engine_lower = engine.lower()
    # Map aurora engines to their base
    if engine_lower.startswith("aurora-mysql"):
        engine_lower = "mysql"
    elif engine_lower.startswith("aurora-postgresql"):
        engine_lower = "postgres"

    env_config = ENGINE_ENV_VARS.get(engine_lower, ENGINE_ENV_VARS["postgres"])
    env = {}

    if engine_lower == "postgres":
        env[env_config["user_env"]] = master_username
        env[env_config["password_env"]] = master_password
        if db_name:
            env[env_config["database_env"]] = db_name
    elif engine_lower in ("mysql", "mariadb"):
        env[env_config["root_password_env"]] = master_password
        # MYSQL_USER / MARIADB_USER requires a database to grant permissions on
        if not db_name:
            db_name = "main"
        env[env_config["database_env"]] = db_name
        # For non-root users, set engine-specific user env vars (BUG-04)
        if master_username != "root":
            env[env_config["user_env"]] = master_username
            env[env_config["password_env"]] = master_password

    return env
