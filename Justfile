# Get a list of all the tasks
list:
  @just --list --unsorted

# Run tests
test: seed
  cargo test --package lers --lib tests

# Lint the codebase
lint:
  cargo fmt --all
  cargo clippy -- -D warnings
  yamllint -s .

alias t := test
alias l := lint

# Seed the Pebble server with test data
seed: pebble
  poetry run python3 hack/seed.py

# Launch the Let's Encrypt Pebble test server
pebble:
  docker compose down --volumes
  docker compose up -d
