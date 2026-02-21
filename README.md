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
- **Mailpit**: `http://localhost:8025` (catches all outgoing emails)

### Running the App

```bash
just run        # Run the app locally (will warn if Postgres is not running)
```

## Deployment (AWS via SST)

This project uses [SST Ion](https://sst.dev) to deploy to AWS. SST manages:
- The **Lambda** function running the Go app.
- The **RDS Postgres** database inside a VPC.
- All **IAM roles** and **networking** automatically.

### Install SST
```bash
curl -fsSL https://sst.dev/install | bash
```

### Set Secrets (one-time)
```bash
sst secret set JwtSecret <a-long-random-string>
sst secret set DbPassword <a-strong-password>
sst secret set SmtpUser <ses-smtp-username>
sst secret set SmtpPass <ses-smtp-password>
```

### Deploy
```bash
just deploy       # Deploy to production
just deploy-dev   # Deploy a personal dev stage
just destroy      # Remove all dev AWS resources
```

### Stages
| Stage | Purpose |
| :--- | :--- |
| `production` | Live site at `mtn.lu`. Resources are protected from accidental deletion. |
| `dev` | Personal sandbox. Resources are removed on `just destroy`. |
