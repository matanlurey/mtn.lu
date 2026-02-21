# Start the database and pgAdmin if not already running
db:
    #!/usr/bin/env bash
    if [ "$(docker inspect -f '{{{{.State.Running}}}}' mtn-postgres 2>/dev/null)" = "true" ]; then
        echo "Postgres is already running on localhost:5432"
        echo "pgAdmin is already running on http://localhost:5050"
        echo "Mailpit is already running on http://localhost:8025"
    else
        docker compose up -d
        echo "Postgres is running on localhost:5432"
        echo "pgAdmin is starting on http://localhost:5050 (Login: admin@mtn.lu / password123)"
        echo "Mailpit is starting on http://localhost:8025"
    fi

# Stop the database
db-stop:
    docker compose down
    @echo "Postgres stopped"

# Run main.go
run:
    #!/usr/bin/env bash
    if [ "$(docker inspect -f '{{{{.State.Running}}}}' mtn-postgres 2>/dev/null)" != "true" ]; then
        echo "Warning: Postgres is not running. Start it with: just db"
    fi
    go run main.go

# Nuclear reset: Re-initialize the schema (wipes all data!)
db-init: db
    @echo "Resetting database schema..."
    @docker exec -i mtn-postgres psql -U postgres -d mtn_lu < schema.sql
    @echo "Database initialized with fresh schema."

# Deploy to AWS (production)
deploy:
    sst deploy --stage production

# Deploy to a personal dev stage on AWS (for testing)
deploy-dev:
    sst deploy --stage dev

# Remove all AWS resources for a given stage
destroy:
    sst remove --stage dev
