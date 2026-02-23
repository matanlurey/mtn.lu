# Microsites by Matan

This project is a landing page and micro-login for (future) `*.mtn.lu` apps.

What it does:

- Let you request a login (JWT) token with an email address
- Validates the JWT, and allows logging in/out
- Admin users can invite additional users (i.e. adding their email address to the users list)

[![Deploy](https://github.com/matanlurey/mtn.lu/actions/workflows/deploy.yml/badge.svg)](https://github.com/matanlurey/mtn.lu/actions/workflows/deploy.yml)

## Requirements

- [Go](https://go.dev/dl/) (1.25+)
- [just](https://github.com/casey/just) — task runner (`brew install just`)
- [Docker](https://www.docker.com/products/docker-desktop/) or [OrbStack](https://orbstack.dev/) — to run DynamoDB Local
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) — to create local tables

## Development

### Services

```bash
just services-start # Start DynamoDB Local & Mailpit (creates tables automatically)
just services-stop  # Stop all services
just db-reset       # Wipe and recreate the tables
```

Once running, you can access:
- **DynamoDB Local**: `http://localhost:8000`
- **Mailpit**: `http://localhost:8025` (catches all outgoing emails)

### Running the App

```bash
just run           # Run the app locally
```

The app auto-detects local vs Lambda — when not running in Lambda, it connects to DynamoDB Local at `localhost:8000` with dummy credentials.

### DynamoDB Schema

Two tables, both using on-demand billing:

**`users`** — Primary key: `email`
| Field | Type | Description |
| :--- | :--- | :--- |
| `email` | String (PK) | User's email address |
| `permissions` | Number | Bit flags (1 = admin) |
| `createdAt` | String | ISO 8601 timestamp |

**`links`** — Primary key: `token`, GSI: `email-index` (email + createdAt)
| Field | Type | Description |
| :--- | :--- | :--- |
| `token` | String (PK) | Random hex token |
| `email` | String | User's email address |
| `createdAt` | String | ISO 8601 timestamp |
| `expiresAt` | Number | Unix timestamp (TTL — auto-deleted by DynamoDB) |
| `usedAt` | String | ISO 8601 timestamp (empty if unused) |

## Deployment (AWS via SST)

This project uses [SST Ion](https://sst.dev) to deploy to AWS. SST manages:
- The **Lambda** function running the Go app.
- Two **DynamoDB** tables (`users` and `links`).
- All **IAM roles** automatically.

No VPC, NAT gateway, or connection pooling required.

### Install SST
```bash
curl -fsSL https://sst.dev/install | bash
```

### Set Secrets (one-time)
```bash
sst secret set JWT_SECRET <a-long-random-string>
sst secret set SMTP_USER <ses-smtp-username>
sst secret set SMTP_PASS <ses-smtp-password>
sst secret set ADMIN_USER <admin-email-address>
```

### Deploy
```bash
just deploy-prod   # Deploy to production
just deploy-dev    # Deploy a personal dev stage
just destroy-prod  # Remove all production AWS resources
just destroy-dev   # Remove all dev AWS resources
```

### Stages
| Stage | Purpose |
| :--- | :--- |
| `production` | Live site at `mtn.lu`. Resources are protected from accidental deletion. |
| `dev` | Personal sandbox. Resources are removed on `just destroy-dev`. |
