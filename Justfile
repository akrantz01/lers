set dotenv-load := true

# Get a list of all the tasks
list:
  @just --list --unsorted

# Run tests
test FEATURES="http-01,dns-01,tls-alpn-01" *FLAGS="": seed
  cargo test --features {{FEATURES}} {{FLAGS}}

# Run integration tests
integration-test FEATURES="http-01,tls-alpn-01,dns-01,dns-01-cloudflare" *FLAGS="": seed
  cargo test --features integration --features {{FEATURES}} {{FLAGS}}

# Lint the codebase
lint:
  cargo fmt --all
  cargo clippy -- -D warnings
  yamllint -s .

# Preview generated documentation
docs:
  RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --open --all-features

alias t := test
alias it := integration-test
alias l := lint

# Seed the Pebble server with test data
seed: pebble
  poetry run python3 hack/seed.py

# Launch the Let's Encrypt Pebble test server
pebble:
  docker compose down --volumes
  docker compose up -d
