# This makefile is used to make it easier to get the project set up
# to be ready for development work in the local sandbox.
# example: "make setup"

LINT_DIRS=keyprotect test/unit

setup: deps

all: setup test-unit lint

ci: all

publish-release: build-dist publish-dist

deps:
	uv sync --all-groups

detect-secrets:
	detect-secrets scan --update .secrets.baseline
	detect-secrets audit .secrets.baseline

test: test-unit test-int

test-unit:
	uv run pytest --cov=keyprotect test/unit

test-int:
	uv run pytest test/integration

test-examples:
	uv run pytest examples

lint:
	uv run pylint ${LINT_DIRS} --exit-zero

build-dist:
	rm -rf dist
	uv build

# This target requires the TWINE_PASSWORD env variable to be set to the user's pypi.org API token.
publish-dist:
	TWINE_USERNAME=__token__ uv run twine upload --non-interactive --verbose dist/*
