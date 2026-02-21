# Start the database if not already running
db:
    #!/usr/bin/env bash
    if [ "$(docker inspect -f '{{{{.State.Running}}}}' mtn-postgres 2>/dev/null)" = "true" ]; then
        echo "Postgres is already running on localhost:5432"
    else
        docker compose up -d
        echo "Postgres is running on localhost:5432"
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
