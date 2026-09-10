# Colors for output messages
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[0;33m
# Reset color
NC=\033[0m

.PHONY: test race bench cover lint check clean

# Run the test suite with coverage; artifacts go to tmp/
test:
	@printf "$(YELLOW)Running tests...$(NC)\n"
	@mkdir -p tmp
	@go test -v \
		-timeout 5m \
		-cover \
		-coverpkg=./... \
		-coverprofile=tmp/coverage.out \
		./...
	@printf "$(GREEN)Tests passed.$(NC)\n"

# Run the tests under the race detector
race:
	@printf "$(YELLOW)Running tests with the race detector...$(NC)\n"
	@go test -race -timeout 10m ./...
	@printf "$(GREEN)No races detected.$(NC)\n"

# Run the benchmarks; no tests, allocations reported
bench:
	@printf "$(YELLOW)Running benchmarks...$(NC)\n"
	@mkdir -p tmp
	@go test -bench . -benchmem -benchtime 2s -run "^$$" ./... | tee tmp/bench.txt
	@printf "$(GREEN)Written to tmp/bench.txt$(NC)\n"

# Render the coverage profile as HTML
cover: test
	@go tool cover -html=tmp/coverage.out -o tmp/coverage.html
	@printf "$(GREEN)Written to tmp/coverage.html$(NC)\n"

# Formatting and static analysis
lint:
	@printf "$(YELLOW)Checking formatting...$(NC)\n"
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || { printf "$(RED)Files above are not gofmt-ed.$(NC)\n"; exit 1; }
	@printf "$(YELLOW)Running go vet...$(NC)\n"
	@go vet ./...
	@printf "$(GREEN)Clean.$(NC)\n"

# Everything CI runs
check: lint race

# Remove build and test artifacts
clean:
	@printf "$(RED)Cleaning up temporary files...$(NC)\n"
	@rm -rf tmp
