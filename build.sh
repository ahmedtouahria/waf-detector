#!/bin/bash

echo "wafw00f-go - Build and Test Script"
echo "===================================="
echo ""

echo "Step 1: Initialize Go module..."
go mod tidy

echo ""
echo "Step 2: Building binary..."
make build

echo ""
echo "Step 3: Running example scan..."
./bin/wafw00f-go -u https://cloudflare.com --timeout 5

echo ""
echo "Build complete! Binary available at: bin/wafw00f-go"
echo ""
echo "Usage examples:"
echo "  ./bin/wafw00f-go -u https://example.com"
echo "  ./bin/wafw00f-go -l examples/targets.txt -t 20 -o results.json -f json"
echo "  ./bin/wafw00f-go -u https://example.com --debug"
