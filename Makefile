.PHONY: install uninstall check test help build release clean

BIN_NAME := which-dex
INSTALL_PATH := /usr/local/bin/$(BIN_NAME)
BIN_PATH := $(CURDIR)/target/release/$(BIN_NAME)

help:
	@echo "$(BIN_NAME) - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make check      - Check if dependencies are installed"
	@echo "  make build      - Build debug binary"
	@echo "  make release    - Build release binary (locked)"
	@echo "  make install    - Install $(BIN_NAME) command globally (symlink)"
	@echo "  make uninstall  - Remove installed $(BIN_NAME) command"
	@echo "  make test       - Run a simple smoke test ($(BIN_NAME) --help)"
	@echo "  make clean      - cargo clean"

check:
	@echo "Checking dependencies..."
	@command -v cargo >/dev/null 2>&1 || { echo "❌ cargo is not installed. Install Rust toolchain and retry"; exit 1; }
	@echo "✓ cargo is installed"
	@echo "✓ All dependencies are satisfied"

build: check
	cargo build

release: check
	cargo build --release --locked

install: release
	@echo "Installing $(BIN_NAME) command..."
	@test -f "$(BIN_PATH)" || { echo "❌ $(BIN_PATH) not found (build failed?)"; exit 1; }
	@ln -sf "$(BIN_PATH)" "$(INSTALL_PATH)" || { \
		echo "❌ Failed to link into $(INSTALL_PATH). Try: sudo make install"; \
		exit 1; \
	}
	@echo "✓ Installed to $(INSTALL_PATH)"
	@echo ""
	@echo "You can now use: $(BIN_NAME) --help"

uninstall:
	@echo "Uninstalling $(BIN_NAME) command..."
	@rm -f "$(INSTALL_PATH)" || { \
		echo "❌ Failed to remove $(INSTALL_PATH). Try: sudo make uninstall"; \
		exit 1; \
	}
	@echo "✓ Removed $(INSTALL_PATH)"

test: check
	@echo "Running smoke test..."
	@echo ""
	@$(BIN_PATH) --help >/dev/null
	@echo "✓ $(BIN_NAME) --help works"

clean:
	cargo clean

