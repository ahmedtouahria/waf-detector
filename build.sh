#!/bin/bash

echo "waf-detector - Build and Test Script"
echo "===================================="
echo ""

echo "Step 1: Initialize Go module..."
go mod tidy

echo ""
echo "Step 2: Building binary..."
make build

echo ""
echo "Step 3: Running example scan..."
./bin/waf-detector -u https://cloudflare.com --timeout 5

echo ""
echo "Build complete! Binary available at: bin/waf-detector"
echo ""
echo "Usage examples:"
echo "  ./bin/waf-detector -u https://example.com"
echo "  ./bin/waf-detector -l examples/targets.txt -t 20 -o results.json -f json"
echo "  ./bin/waf-detector -u https://example.com --debug"
