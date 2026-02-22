# Start the database and pgAdmin if not already running
services-start:
    #!/usr/bin/env bash
    if [ -n "$(docker ps -q -f name=mtn-postgres -f status=running)" ]; then
        echo "Services are already running."
    else
        docker compose up -d --remove-orphans
        echo "Postgres is running on localhost:5432"
        echo "pgAdmin is starting on http://localhost:5050 (Login: admin@mtn.lu / password123)"
        echo "Mailpit is starting on http://localhost:8025"
    fi

# Stop the database
services-stop:
    docker compose down
    @echo "Services stopped"

# Run main.go
run:
    #!/usr/bin/env bash
    if [ -z "$(docker ps -q -f name=mtn-postgres -f status=running)" ]; then
        echo "Warning: Postgres is not running. Start it with: just services-start"
    fi
    go run main.go

# Nuclear reset: Delete all data
db-reset:
    @echo "Resetting database..."
    @docker exec -i mtn-postgres psql -U postgres -d mtn_lu < reset.sql

# Deploy to AWS (production)
deploy-prod:
    sst deploy --stage production

# Remove all AWS resources for production stage
destroy-prod:
    sst remove --stage production

# Deploy to a personal dev stage on AWS (for testing)
deploy-dev:
    sst deploy --stage dev

# Remove all AWS resources for the dev stage
destroy-dev:
    sst remove --stage dev
