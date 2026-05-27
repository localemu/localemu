IMAGE_NAME ?= localemu/localemu
DEFAULT_TAG ?= latest
VENV_BIN ?= python3 -m venv
VENV_DIR ?= .venv
PIP_CMD ?= pip3
TEST_PATH ?= .
TEST_EXEC ?= python -m
PYTEST_LOGLEVEL ?= warning

uname_m := $(shell uname -m)
ifeq ($(uname_m),x86_64)
PLATFORM ?= amd64
else
PLATFORM ?= arm64
endif

ifeq ($(OS), Windows_NT)
	VENV_ACTIVATE = $(VENV_DIR)/Scripts/activate
else
	VENV_ACTIVATE = $(VENV_DIR)/bin/activate
endif

VENV_RUN = . $(VENV_ACTIVATE)

usage:                    ## Show this help
	@grep -Fh "##" $(MAKEFILE_LIST) | grep -Fv fgrep | sed -e 's/:.*##\s*/##/g' | awk -F'##' '{ printf "%-25s %s\n", $$1, $$2 }'

$(VENV_ACTIVATE): pyproject.toml
	test -d $(VENV_DIR) || $(VENV_BIN) $(VENV_DIR)
	$(VENV_RUN); $(PIP_CMD) install --upgrade pip setuptools wheel
	touch $(VENV_ACTIVATE)

venv: $(VENV_ACTIVATE)    ## Create a new (empty) virtual environment

freeze:                   ## Run pip freeze -l in the virtual environment
	@$(VENV_RUN); pip freeze -l

install-basic: venv       ## Install basic dependencies for CLI usage into venv
	$(VENV_RUN); $(PIP_CMD) install $(PIP_OPTS) -e .

install-runtime: venv     ## Install dependencies for the localemu runtime into venv
	$(VENV_RUN); $(PIP_CMD) install $(PIP_OPTS) -e ".[runtime]"

install-test: venv        ## Install requirements to run tests into venv
	$(VENV_RUN); $(PIP_CMD) install $(PIP_OPTS) -e ".[test]"

install-dev: venv         ## Install developer requirements into venv
	$(VENV_RUN); $(PIP_CMD) install $(PIP_OPTS) -e ".[dev]"

install-dev-types: venv   ## Install developer requirements incl. type hints into venv
	$(VENV_RUN); $(PIP_CMD) install $(PIP_OPTS) -e ".[typehint]"

install-s3: venv          ## Install dependencies for the localemu runtime for s3-only into venv
	$(VENV_RUN); $(PIP_CMD) install $(PIP_OPTS) -e ".[base-runtime]"

install: install-dev      ## Install full dependencies into venv

entrypoints: install-dev
	$(VENV_RUN); python -m plux entrypoints
	@# make sure that the plux.ini file with the entrypoints has correctly been created
	@test -s plux.ini || (echo "Entrypoints were not correctly created! Aborting!" && exit 1)

dist:                     ## Build source and built (wheel) distributions of the current version
	$(VENV_RUN); pip install --upgrade build twine; python -m build

publish: clean-dist dist  ## Publish the library to the central PyPi repository
	# make sure the dist archive contains a non-empty entry_points.txt file before uploading
	tar --wildcards --to-stdout -xf dist/localemu*.tar.gz "localemu*/src/localemu.egg-info/entry_points.txt" | grep . > /dev/null 2>&1 || (echo "Refusing upload, localemu dist does not contain entrypoints." && exit 1)
	$(VENV_RUN); twine upload dist/*

coveralls:         		  ## Publish coveralls metrics
	$(VENV_RUN); coveralls

start:             		  ## Manually start the local infrastructure for testing
	($(VENV_RUN); python3 -m localemu.runtime.main)

docker-run-tests:		  ## Initializes the test environment and runs the tests in a docker container
	docker run -e LOCALEMU_INTERNAL_TEST_COLLECT_METRIC=1 -e DOCKERHUB_USERNAME -e DOCKERHUB_PASSWORD --entrypoint= -v `pwd`/.git:/opt/code/localemu/.git -v `pwd`/.test_durations:/opt/code/localemu/.test_durations -v `pwd`/tests/:/opt/code/localemu/tests/ -v `pwd`/dist/:/opt/code/localemu/dist/ -v `pwd`/target/:/opt/code/localemu/target/ -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/localemu:/var/lib/localemu  \
		$(IMAGE_NAME):$(DEFAULT_TAG) \
	    bash -c "make install-test && DEBUG=$(DEBUG) PYTEST_LOGLEVEL=$(PYTEST_LOGLEVEL) PYTEST_ARGS='$(PYTEST_ARGS)' COVERAGE_FILE='$(COVERAGE_FILE)' JUNIT_REPORTS_FILE=$(JUNIT_REPORTS_FILE) TEST_PATH='$(TEST_PATH)' LAMBDA_IGNORE_ARCHITECTURE=1 LAMBDA_INIT_POST_INVOKE_WAIT_MS=50 TINYBIRD_PYTEST_ARGS='$(TINYBIRD_PYTEST_ARGS)' TINYBIRD_DATASOURCE='$(TINYBIRD_DATASOURCE)' TINYBIRD_TOKEN='$(TINYBIRD_TOKEN)' TINYBIRD_URL='$(TINYBIRD_URL)' CI_REPOSITORY_NAME='$(CI_REPOSITORY_NAME)' CI_WORKFLOW_NAME='$(CI_WORKFLOW_NAME)' CI_COMMIT_BRANCH='$(CI_COMMIT_BRANCH)' CI_COMMIT_SHA='$(CI_COMMIT_SHA)' CI_JOB_URL='$(CI_JOB_URL)' CI_JOB_NAME='$(CI_JOB_NAME)' CI_JOB_ID='$(CI_JOB_ID)' CI='$(CI)' TEST_AWS_REGION_NAME='${TEST_AWS_REGION_NAME}' TEST_AWS_ACCESS_KEY_ID='${TEST_AWS_ACCESS_KEY_ID}' TEST_AWS_ACCOUNT_ID='${TEST_AWS_ACCOUNT_ID}' make test-coverage"

docker-run-tests-s3-only:		  ## Initializes the test environment and runs the tests in a docker container for the S3 only image
	# TODO: We need node as it's a dependency of the InfraProvisioner at import time, remove when we do not need it anymore
	# g++ is a workaround to fix the JPype1 compile error on ARM Linux "gcc: fatal error: cannot execute ‘cc1plus’" because the test dependencies include the runtime dependencies.
	docker run -e LOCALEMU_INTERNAL_TEST_COLLECT_METRIC=1 --entrypoint= -v `pwd`/.git:/opt/code/localemu/.git -v `pwd`/tests/:/opt/code/localemu/tests/ -v `pwd`/target/:/opt/code/localemu/target/ -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/localemu:/var/lib/localemu \
		$(IMAGE_NAME):$(DEFAULT_TAG) \
	    bash -c "apt-get update && apt-get install -y g++ git && make install-test && apt-get install -y --no-install-recommends gnupg && mkdir -p /etc/apt/keyrings && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && echo \"deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_18.x nodistro main\" > /etc/apt/sources.list.d/nodesource.list && apt-get update && apt-get install -y --no-install-recommends nodejs && DEBUG=$(DEBUG) PYTEST_LOGLEVEL=$(PYTEST_LOGLEVEL) PYTEST_ARGS='$(PYTEST_ARGS)' TEST_PATH='$(TEST_PATH)' TINYBIRD_PYTEST_ARGS='$(TINYBIRD_PYTEST_ARGS)' TINYBIRD_DATASOURCE='$(TINYBIRD_DATASOURCE)' TINYBIRD_TOKEN='$(TINYBIRD_TOKEN)' TINYBIRD_URL='$(TINYBIRD_URL)' CI_COMMIT_BRANCH='$(CI_COMMIT_BRANCH)' CI_COMMIT_SHA='$(CI_COMMIT_SHA)' CI_JOB_URL='$(CI_JOB_URL)' CI_JOB_NAME='$(CI_JOB_NAME)' CI_JOB_ID='$(CI_JOB_ID)' CI='$(CI)' make test"


docker-cp-coverage:
	@echo 'Extracting .coverage file from Docker image'; \
		id=$$(docker create localemu/localemu); \
		docker cp $$id:/opt/code/localemu/.coverage .coverage; \
		docker rm -v $$id

test:              		  ## Run automated tests
	($(VENV_RUN); $(TEST_EXEC) pytest --durations=10 --log-cli-level=$(PYTEST_LOGLEVEL) --junitxml=$(JUNIT_REPORTS_FILE) $(PYTEST_ARGS) $(TEST_PATH))

test-coverage: LOCALEMU_INTERNAL_TEST_COLLECT_METRIC = 1
test-coverage: TEST_EXEC = python -m coverage run $(COVERAGE_ARGS) -m
test-coverage: test	  ## Run automated tests and create coverage report

lint:              		  ## Run code linter to check code style, check if formatter would make changes and check if dependency pins need to be updated
	@[ -f src/localemu/__init__.py ] && echo "src/localemu/__init__.py will break packaging." && exit 1 || :
	($(VENV_RUN); python -m ruff check --output-format=full . && python -m ruff format --check --diff .)
	$(VENV_RUN); pre-commit run check-pinned-deps-for-needed-upgrade --files pyproject.toml # run pre-commit hook manually here to ensure that this check runs in CI as well
	$(VENV_RUN); openapi-spec-validator src/localemu/openapi.yaml
	$(VENV_RUN); cd src && mypy --install-types --non-interactive
	$(VENV_RUN); deptry .

lint-modified:     		  ## Run code linter to check code style, check if formatter would make changes on modified files, and check if dependency pins need to be updated because of modified files
	($(VENV_RUN); python -m ruff check --output-format=full `git diff --diff-filter=d --name-only HEAD | grep '\.py$$' | xargs` && python -m ruff format --check `git diff --diff-filter=d --name-only HEAD | grep '\.py$$' | xargs`)
	$(VENV_RUN); pre-commit run check-pinned-deps-for-needed-upgrade --files $(git diff main --name-only) # run pre-commit hook manually here to ensure that this check runs in CI as well

check-aws-markers:     		  ## Lightweight check to ensure all AWS tests have proper compatibility markers set
	($(VENV_RUN); python -m pytest --co tests/aws/)

format:            		  ## Run ruff to format the whole codebase
	($(VENV_RUN); python -m ruff check --output-format=full --fix .; python -m ruff format .)

format-modified:          ## Run ruff to format only modified code
	($(VENV_RUN); \
	  python -m ruff check --output-format=full --fix `git diff --diff-filter=d --name-only HEAD | grep '\.py$$' | xargs`; \
	  python -m ruff format `git diff --diff-filter=d --name-only HEAD | grep '\.py$$' | xargs`)

asf-regenerate:                   ## Regenerate ASF APIs
	$(VENV_RUN); python -m localemu.aws.scaffold upgrade
	@echo 'Removing unused imports from generated modules'
	$(VENV_RUN); python -m ruff check --select F401 --unsafe-fixes --fix src/localemu/aws/api/ --config "lint.preview = true"
	$(VENV_RUN); python -m ruff check --output-format=full --fix src/localemu/aws/api/
	$(VENV_RUN); python -m ruff format src/localemu/aws/api/

init-precommit:    		  ## install te pre-commit hook into your local git repository
	($(VENV_RUN); pre-commit install)

docker-build:
	IMAGE_NAME=$(IMAGE_NAME) PLATFORM=$(PLATFORM) ./bin/docker-helper.sh build

clean:             		  ## Clean up (npm dependencies, downloaded infrastructure code, compiled Java classes)
	rm -rf .filesystem
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf src/*.egg-info
	rm -rf $(VENV_DIR)

clean-dist:				  ## Clean up python distribution directories
	rm -rf dist/ build/
	rm -rf src/*.egg-info

.PHONY: usage freeze install-basic install-runtime install-test install-dev install entrypoints dist publish coveralls start docker-run-tests docker-cp-coverage test test-coverage lint lint-modified format format-modified asf-regenerate init-precommit clean clean-dist upgrade-pinned-dependencies
