# magnets

`magnets` is an asynchronous CLI client for the [Torznab](https://torznab.github.io/spec-1.3-draft/index.html) search API. It works with a full Torznab endpoint you control, so the same command can query self-hosted Bitmagnet, Jackett, or any other compatible indexer.

It does not download torrent content. It prints the metadata and magnet or download URL returned by the indexer.

## Install

```bash
cargo install --path .
```

## Search known indexers

Pass the complete Torznab endpoint, rather than a web UI URL:

```bash
magnets search "Ubuntu 24.04" \
  --indexer http://localhost:3333/torznab
```

Use several endpoints concurrently:

```bash
magnets search "Fedora Workstation" \
  -i http://localhost:3333/torznab \
  -i http://localhost:9117/api/v2.0/indexers/all/results/torznab/api \
  --api-key "$JACKETT_API_KEY"
```

For Torznab providers that use the usual API-key parameter, use `--api-key` (or `MAGNETS_API_KEY`):

```bash
magnets search "debian 12" \
  -i http://localhost:9117/api/v2.0/indexers/all/results/torznab/api \
  --api-key "$JACKETT_API_KEY"
```

`MAGNETS_INDEXERS` may contain a comma-separated list of endpoint URLs, which avoids repeating `--indexer`.

## Discover public Bitmagnet instances

Bitmagnet is MIT-licensed, self-hosted torrent indexer software and exposes a Torznab endpoint at `/torznab`. The `discover` command invokes your locally configured [`shodan` CLI](https://cli.shodan.io/) with Bitmagnet's HTTP-title fingerprint. Every candidate is then probed concurrently with `?t=caps`; only Torznab responses are printed.

```bash
# Find and validate up to 50 candidates.
magnets discover

# Search the five fastest cached endpoints. `search` is optional.
magnets "ubuntu 24.04"
magnets search "ubuntu 24.04" -n 10

# Refresh discovery and search in one command.
magnets search "ubuntu 24.04" --shodan -n 10
```

`discover` writes verified endpoints to `~/.config/magnets/indexers` (or `$XDG_CONFIG_HOME/magnets/indexers`). Bare searches use that cache automatically and query up to ten endpoints; increase `--fanout` if needed. `-n` limits the combined output; `--per-source-limit` controls the request size per endpoint.

Use `--verbose` to see rejected candidates, `--shodan-limit` to change the candidate count, `--concurrency` to bound parallel HTTP requests, and `--json` for machine-readable output. A custom `--shodan-query` is available when you have a different Torznab-compatible software fingerprint to validate.

The Shodan scan is opt-in for searches (`--shodan`). For controlled or authenticated deployments, use an explicit `--indexer` endpoint instead.

## Development

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```
