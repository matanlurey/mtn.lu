# Microsites by Matan

This project is a landing page and micro-login for (future) `*.mtn.lu` apps.

What it does:

- Let you request a login (JWT) token with an email address
- Validates the JWT, and allows logging in/out
- Admin users can invite additional users (i.e. adding their email address to the users list)

## Requirements

- [Go](https://go.dev/dl/) (1.21+)
- [just](https://github.com/casey/just) — task runner (`brew install just`)
- [Docker](https://www.docker.com/products/docker-desktop/) or [OrbStack](https://orbstack.dev/) — to run Postgres locally

## Development

### Database

```bash
just db         # Start Postgres & pgAdmin (skips if already running)
just db-stop    # Stop Postgres & pgAdmin
just db-init    # Wipe and re-initialize the schema (uses schema.sql)
```

Once running, you can access:
- **Postgres**: `localhost:5432`
- **pgAdmin**: `http://localhost:5050` (Login: `admin@mtn.lu` / `password123`)

### Running the App

```bash
just run        # Run the app (will warn if Postgres is not running)
```
