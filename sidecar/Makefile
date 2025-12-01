.PHONY: build test clean docker-build docker-push

# Binary name
BINARY=coco-secure-access

# Docker image
IMAGE=quay.io/confidential-devhub/coco-secure-access
TAG?=latest

build:
	@echo "Building $(BINARY)..."
	@go build -ldflags="-w -s" -o $(BINARY) .
	@echo "Build complete: $(BINARY)"

test:
	@echo "Running tests..."
	@go test -v ./...

clean:
	@echo "Cleaning..."
	@rm -f $(BINARY)
	@go clean

docker-build:
	@echo "Building Docker image $(IMAGE):$(TAG)..."
	@docker build --platform linux/amd64 -t $(IMAGE):$(TAG) .

docker-push: docker-build
	@echo "Pushing Docker image $(IMAGE):$(TAG)..."
	@docker push $(IMAGE):$(TAG)

fmt:
	@echo "Formatting code..."
	@go fmt ./...

vet:
	@echo "Running go vet..."
	@go vet ./...

lint:
	@echo "Running linter..."
	@golangci-lint run

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
