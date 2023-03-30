# Get a list of all the tasks
list:
  @just --list --unsorted

# Run tests
test *FLAGS="--features dns-01": seed
  cargo test {{FLAGS}}

# Lint the codebase
lint:
  cargo fmt --all
  cargo clippy -- -D warnings
  yamllint -s .

# Preview generated documentation
docs:
  RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --open --all-features

alias t := test
alias l := lint

# Seed the Pebble server with test data
seed: pebble
  poetry run python3 hack/seed.py

# Launch the Let's Encrypt Pebble test server
pebble:
  docker compose down --volumes
  docker compose up -d
