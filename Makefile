# Validation targets used by both Gitea and GitHub Actions.

.PHONY: ci test lint compile

ci: lint test compile

test:
	pytest -n auto -q

lint:
	ruff check .

compile:
	python -m compileall -q src tests
