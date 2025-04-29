BINARY := dsde-dedupe
CMD_DIR := cmd/server

.PHONY: all build run test clean

all: build

# Compile the server into ./bin/dsde-dedupe
build:
	mkdir -p bin
	go build -o bin/$(BINARY) ./$(CMD_DIR)

# Run the server (loads latest code)
run:
	go run ./$(CMD_DIR)

# Run all Go tests
test:
	go test ./...

clean:
	rm -rf bin
