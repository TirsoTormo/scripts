.PHONY: dev test lint fmt check clean sync upgrade

# Show help
dev:
	uv run python -m argos --help

# Run tests
test:
	uv run pytest

# Lint code
lint:
	uv run ruff check src

# Format code
fmt:
	uv run ruff format src
	uv run ruff check --fix src

# Type check
typecheck:
	uv run mypy src

# Run all checks
check: fmt lint typecheck test
	@echo "All checks passed!"

# Clean
clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +

# Sync dependencies
sync:
	uv sync

# Upgrade dependencies
upgrade:
	uv lock --upgrade
	uv sync
