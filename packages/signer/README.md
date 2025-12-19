# @pomade/signer

Standalone signer service for pomade. This service manages multisig sessions, handles signing requests, and coordinates recovery flows.

## Configuration

Required environment variables:
- `POMADE_SECRET`: Your nostr private key (hex or nsec format)
- `POMADE_RELAYS`: Comma-separated list of relay URLs

Optional environment variables:
- `POMADE_DB_PATH`: Path to SQLite database (default: `./pomade-signer.db`)

## Running

From the repository root:

```sh
mkdir -p data
cp packages/signer/.env{.example,} # Edit the env file to fill in your details
docker build -f packages/signer/Dockerfile -t pomade-signer .
docker run -v $(pwd)/data:/data --env-file packages/signer/.env pomade-signer
```

From dockerhub:

```sh
```
