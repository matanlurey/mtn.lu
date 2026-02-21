# Start the database and pgAdmin if not already running
db:
    #!/usr/bin/env bash
    if [ "$(docker inspect -f '{{{{.State.Running}}}}' mtn-postgres 2>/dev/null)" = "true" ]; then
        echo "Postgres is already running on localhost:5432"
        echo "pgAdmin is already running on http://localhost:5050"
    else
        docker compose up -d
        echo "Postgres is running on localhost:5432"
        echo "pgAdmin is starting on http://localhost:5050 (Login: admin@mtn.lu / password123)"
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
