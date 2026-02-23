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
        --table-name users \
        --attribute-definitions AttributeName=email,AttributeType=S \
        --key-schema AttributeName=email,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST $ENDPOINT || true

    # Links Table
    aws dynamodb create-table \
        --table-name links \
        --attribute-definitions AttributeName=token,AttributeType=S AttributeName=email,AttributeType=S AttributeName=createdAt,AttributeType=S \
        --key-schema AttributeName=token,KeyType=HASH \
        --global-secondary-indexes \
            'IndexName=email-index,KeySchema=[{AttributeName=email,KeyType=HASH},{AttributeName=createdAt,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
        --billing-mode PAY_PER_REQUEST $ENDPOINT || true
    
    aws dynamodb update-time-to-live \
        --table-name links \
        --time-to-live-specification "Enabled=true,AttributeName=expiresAt" $ENDPOINT || true

# Reset tables
db-reset:
    #!/usr/bin/env bash
    ENDPOINT="--endpoint-url http://localhost:8000 --region us-west-1 --no-cli-pager"
    aws dynamodb delete-table --table-name users $ENDPOINT || true
    aws dynamodb delete-table --table-name links $ENDPOINT || true
    sleep 1
    just db-setup

# Run main.go
run:
    #!/usr/bin/env bash
    REV=$(git rev-parse --short HEAD)
    DYNAMODB_URL=http://localhost:8000 go run -ldflags "-X mtn.lu/landing/internal/auth.Revision=$REV" .

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
