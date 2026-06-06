.PHONY: test lint format-check check help

help:
	python -m offline_packet_analyzer --help

test:
	python -m pytest

lint:
	python -m ruff check .

format-check:
	python -m ruff format --check .

check: lint format-check test

