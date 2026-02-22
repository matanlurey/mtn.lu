# Start DynamoDB Local and Mailpit
services-start:
    #!/usr/bin/env bash
    if [ -n "$(docker ps -q -f name=mtn-dynamodb -f status=running)" ]; then
        echo "Services are already running."
    else
        docker compose up -d --remove-orphans
        echo "DynamoDB Local: http://localhost:8000"
        echo "Mailpit: http://localhost:8025"
        sleep 1
        just db-setup
    fi

# Stop all services
services-stop:
    docker compose down
    @echo "Services stopped"

# Create the local DynamoDB tables
db-setup:
    #!/usr/bin/env bash
    ENDPOINT="--endpoint-url http://localhost:8000 --region us-west-1 --no-cli-pager"
    
    # Users Table
    aws dynamodb create-table \
        --table-name mtn-lu-users \
        --attribute-definitions AttributeName=email,AttributeType=S \
        --key-schema AttributeName=email,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST $ENDPOINT || true

    # Links Table
    aws dynamodb create-table \
        --table-name mtn-lu-links \
        --attribute-definitions AttributeName=token,AttributeType=S AttributeName=email,AttributeType=S AttributeName=createdAt,AttributeType=S \
        --key-schema AttributeName=token,KeyType=HASH \
        --global-secondary-indexes \
            'IndexName=email-index,KeySchema=[{AttributeName=email,KeyType=HASH},{AttributeName=createdAt,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
        --billing-mode PAY_PER_REQUEST $ENDPOINT || true
    
    aws dynamodb update-time-to-live \
        --table-name mtn-lu-links \
        --time-to-live-specification "Enabled=true,AttributeName=expiresAt" $ENDPOINT || true

# Reset tables
db-reset:
    #!/usr/bin/env bash
    ENDPOINT="--endpoint-url http://localhost:8000 --region us-west-1 --no-cli-pager"
    aws dynamodb delete-table --table-name mtn-lu-users $ENDPOINT || true
    aws dynamodb delete-table --table-name mtn-lu-links $ENDPOINT || true
    sleep 1
    just db-setup

# Run main.go
run:
    #!/usr/bin/env bash
    USERS_TABLE=mtn-lu-users LINKS_TABLE=mtn-lu-links DYNAMO_ENDPOINT=http://localhost:8000 go run main.go
