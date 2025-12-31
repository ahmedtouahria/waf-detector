.PHONY: all build test clean install lint fmt vet coverage help

# Variables
BINARY_NAME=waf-detector
VERSION?=dev
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Build directory
BUILD_DIR=bin

all: clean lint test build

## build: Build the binary
build:
	@echo "Building ${BINARY_NAME}..."
	@mkdir -p ${BUILD_DIR}
	$(GOBUILD) ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} -v
	@echo "Binary built: ${BUILD_DIR}/${BINARY_NAME}"

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -timeout 30s ./...

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.txt -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report: coverage.html"

## bench: Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

## clean: Clean build files
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf ${BUILD_DIR}
	rm -f coverage.txt coverage.html

## install: Install the binary
install: build
	@echo "Installing ${BINARY_NAME}..."
	@cp ${BUILD_DIR}/${BINARY_NAME} $(GOPATH)/bin/${BINARY_NAME}
	@echo "Installed to $(GOPATH)/bin/${BINARY_NAME}"

## lint: Run linter
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## run: Run the application
run: build
	@./${BUILD_DIR}/${BINARY_NAME}

## run-example: Run example scan
run-example: build
	@./${BUILD_DIR}/${BINARY_NAME} -u https://example.com

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t ${BINARY_NAME}:${VERSION} .

## docker-run: Run Docker container
docker-run:
	docker run --rm ${BINARY_NAME}:${VERSION}

## release: Build for multiple platforms
release:
	@echo "Building for multiple platforms..."
	@mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=amd64 $(GOBUILD) ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64
	GOOS=linux GOARCH=arm64 $(GOBUILD) ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-arm64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-amd64
	GOOS=darwin GOARCH=arm64 $(GOBUILD) ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-arm64
	GOOS=windows GOARCH=amd64 $(GOBUILD) ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe
	@echo "Release builds complete in ${BUILD_DIR}/"

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
