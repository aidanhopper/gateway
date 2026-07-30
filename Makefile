.PHONY: build release test clean install

BIN_DIR := bin
DIST_DIR := dist
BINARY_NAME := gateway

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/gateway
	@echo "[SUCCESS] Built $(BIN_DIR)/$(BINARY_NAME)"

release: clean
	@mkdir -p $(DIST_DIR)
	@echo "[INFO] Cross-compiling release binaries (CGO_ENABLED=0)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/gateway
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/gateway
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/gateway
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/gateway
	@echo "[SUCCESS] Release binaries generated in $(DIST_DIR)/:"
	@ls -lh $(DIST_DIR)

test:
	go test ./...

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

.PHONY: build release test clean install install-client install-server

install: build
	@./deploy/install.sh --client

install-client: build
	@./deploy/install.sh --client

install-server: build
	@sudo ./deploy/install.sh --server
