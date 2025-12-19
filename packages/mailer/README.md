# @pomade/mailer

Standalone mailer service for pomade. This service listens for recovery method challenges and recovery challenges on nostr relays and sends validation/recovery emails.

## Configuration

Required environment variables:
- `POMADE_SECRET`: The mailer's hex nostr private key
- `POMADE_RELAYS`: Comma-separated list of relay URLs

Optional environment variables:
- `POMADE_DB_PATH`: Path to SQLite database (default: `./pomade-mailer.db`)
- `POMADE_PROVIDER`: Provider type - `console` or `postmark` (default: `console`)

Postmark provider configuration (required if `POMADE_PROVIDER=postmark`):
- `POMADE_POSTMARK_SERVER_TOKEN`: Your Postmark server API token
- `POMADE_POSTMARK_FROM_EMAIL`: Verified sender email address

## Running

From the repository root:

```sh
mkdir -p data
cp packages/mailer/.env{.example,} # Edit the env file to fill in your details
docker build -f packages/mailer/Dockerfile -t pomade-mailer .
docker run -v $(pwd)/data:/data --env-file packages/mailer/.env pomade-mailer
```

From dockerhub:

```sh
```
