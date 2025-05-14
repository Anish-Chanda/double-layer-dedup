# Makefile

# Binaries
BINARY_SERVER   := server
CMD_SERVER_DIR  := cmd/server

BINARY_CLIENT   := client
CMD_CLIENT_DIR  := cmd/client

.PHONY: all build server client run run-server run-client test test-aws clean

all: build

# === build ===
build: server client

server:
	mkdir -p bin
	go build -o bin/$(BINARY_SERVER) ./$(CMD_SERVER_DIR)

client:
	mkdir -p bin
	go build -o bin/$(BINARY_CLIENT) ./$(CMD_CLIENT_DIR)

# === tests ===
# Go unit tests + smoke/integration via test.sh
test:
	go test ./...
	./test.sh

# quick AWS creds / sts check
test-aws:
	go run ./cmd/awschecks/

# === cleanup ===
clean:
	rm -rf bin
