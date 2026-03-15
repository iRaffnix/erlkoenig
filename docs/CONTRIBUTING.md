# Contributing to Erlkoenig

## Branch Model

| Branch | Purpose | Who pushes |
|--------|---------|------------|
| `main` | Stable, always releasable | Only via PR |
| `dev-*` | Working branches (e.g., `dev-rudi`) | Anyone, freely |
| `v*` tags | Releases | Only from `main` |

## Development Workflow

### 1. Work on a dev branch

```bash
git checkout -b dev-yourname
# ... hack, commit, push ...
git push origin dev-yourname
```

Every push triggers CI (`.github/workflows/ci.yml`):
- C runtime build + static binary verification
- Erlang compile, eunit, dialyzer
- Elixir DSL tests
- Release artifact build (uploaded as CI artifacts)

### 2. Test CI artifacts before merging

Don't wait for a release to find bugs. Download the CI artifacts
and install them on a test server:

```bash
# Find the latest CI run
gh run list --branch dev-yourname

# Download artifacts from a specific run
gh run download <run-id> -D /tmp/artifacts

# Install from local artifacts (no GitHub Release needed)
sudo sh install.sh --local /tmp/artifacts
```

Test everything. Fix bugs. Push again. Repeat until it works.

### 3. Create a Pull Request

```bash
gh pr create --base main --title "Short description"
```

CI runs again on the PR. Review, iterate, merge.

### 4. Tag a release

Releases are only created from `main`. The `make tag` target
enforces this and bumps versions in all relevant files:

```bash
git checkout main
git pull origin main

# Bumps rebar.config, app.src, mix.exs, install.sh
# Creates a signed git tag
make tag VERSION=0.2.0

# Push branch + tag (tag triggers release.yml)
git push origin main v0.2.0
```

`release.yml` builds multi-arch artifacts (x86_64 + aarch64) and
publishes them as a GitHub Release with `install.sh` included.

## Install Script

The installer supports two modes:

```bash
# From GitHub Releases (production)
sudo sh install.sh --version v0.2.0

# From local CI artifacts (testing)
sudo sh install.sh --local /tmp/artifacts
```

**Never** instruct users to pipe curl into sh. The correct pattern is:

```bash
curl -fsSL -o install.sh https://github.com/iRaffnix/erlkoenig/releases/latest/download/install.sh
less install.sh        # review first
sudo sh install.sh --version v0.2.0
```

## Build Targets

```bash
make rt            # C runtime (static musl, 68 KB)
make erl           # Erlang compile
make check         # eunit + dialyzer + DSL tests (no root)
make test-rt       # C runtime unit tests (libcheck)
make integration   # E2E tests (requires sudo)
make release       # OTP release tarball
make dsl-escript   # Standalone DSL binary
make go-demos      # Static Go demo binaries
make tag VERSION=X.Y.Z  # Bump + tag (main only)
make clean         # Remove all build artifacts
```

## Setting up `gh` CLI

The `gh` CLI is needed for downloading CI artifacts and creating PRs.

```bash
gh auth login
```

Choose **GitHub.com**, **HTTPS**, **Login with a web browser**.

For private repos, the token needs these scopes:
- `repo` — access private repository content
- `actions:read` — list and download CI artifacts

For public repos, no special scopes are required.

## Project Structure

```
Makefile                 Build orchestration
rebar.config             Erlang build + release config
install.sh               Production installer (ships with releases)
c-runtime/               C source (rt, namespaces, seccomp, netcfg)
  CMakeLists.txt         CMake build
  test/                  libcheck test suite
apps/
  erlkoenig_core/        Erlang control plane (OTP application)
dsl/                     Elixir DSL compiler
  mix.exs                Mix project
  examples/              .exs example configs
demos/                   Go demo binaries (echo, proxy, api)
integration-tests/       E2E test scripts (require root)
docs/                    Documentation
.github/workflows/
  ci.yml                 Tests + artifact build on every push
  release.yml            Multi-arch release on tag push
```
