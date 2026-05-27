"""Definition of Plux extension points (i.e., hooks) for Lambda."""

from localemu.runtime.hooks import hook_spec

HOOKS_LAMBDA_CREATE_FUNCTION_VERSION = "localemu.hooks.lambda_create_function_version"
HOOKS_LAMBDA_DELETE_FUNCTION_VERSION = "localemu.hooks.lambda_delete_function_version"
HOOKS_LAMBDA_START_DOCKER_EXECUTOR = "localemu.hooks.lambda_start_docker_executor"
HOOKS_LAMBDA_PREPARE_DOCKER_EXECUTOR = "localemu.hooks.lambda_prepare_docker_executors"
HOOKS_LAMBDA_INJECT_LAYER_FETCHER = "localemu.hooks.lambda_inject_layer_fetcher"
HOOKS_LAMBDA_INJECT_LDM_PROVISIONER = "localemu.hooks.lambda_inject_ldm_provisioner"
HOOKS_LAMBDA_PREBUILD_ENVIRONMENT_IMAGE = "localemu.hooks.lambda_prebuild_environment_image"
HOOKS_LAMBDA_CREATE_EVENT_SOURCE_POLLER = "localemu.hooks.lambda_create_event_source_poller"
HOOKS_LAMBDA_SET_EVENT_SOURCE_CONFIG_DEFAULTS = (
    "localemu.hooks.lambda_set_event_source_config_defaults"
)

create_function_version = hook_spec(HOOKS_LAMBDA_CREATE_FUNCTION_VERSION)
delete_function_version = hook_spec(HOOKS_LAMBDA_DELETE_FUNCTION_VERSION)
start_docker_executor = hook_spec(HOOKS_LAMBDA_START_DOCKER_EXECUTOR)
prepare_docker_executor = hook_spec(HOOKS_LAMBDA_PREPARE_DOCKER_EXECUTOR)
inject_layer_fetcher = hook_spec(HOOKS_LAMBDA_INJECT_LAYER_FETCHER)
inject_ldm_provisioner = hook_spec(HOOKS_LAMBDA_INJECT_LDM_PROVISIONER)
prebuild_environment_image = hook_spec(HOOKS_LAMBDA_PREBUILD_ENVIRONMENT_IMAGE)
create_event_source_poller = hook_spec(HOOKS_LAMBDA_CREATE_EVENT_SOURCE_POLLER)
set_event_source_config_defaults = hook_spec(HOOKS_LAMBDA_SET_EVENT_SOURCE_CONFIG_DEFAULTS)
