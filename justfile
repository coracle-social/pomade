build-typescript:
  pnpm build

build-pomade-signer-rust:
  cargo build --release --manifest-path pomade-signer-rust/Cargo.toml

build-pomade-signer-go:
  mkdir -p pomade-signer-go/bin
  go build -C pomade-signer-go -o bin/pomade-signer .

format-typescript:
  pnpm format

lint-typescript:
  pnpm lint

format-pomade-signer-rust:
  cargo fmt --manifest-path pomade-signer-rust/Cargo.toml

lint-pomade-signer-rust:
  cargo clippy --manifest-path pomade-signer-rust/Cargo.toml --all-targets -- -D warnings

format-pomade-signer-go:
  gofmt -w pomade-signer-go

lint-pomade-signer-go:
  go vet -C pomade-signer-go ./...

test-typescript:
  pnpm test

test-pomade-signer-rust:
  cargo test --manifest-path pomade-signer-rust/Cargo.toml

test-pomade-signer-go:
  go test -C pomade-signer-go ./...

test-frost-taproot-rust:
  cargo test --manifest-path frost-taproot-rust/Cargo.toml

test-frost-taproot-go:
  go test -C frost-taproot-go ./...

format: format-typescript format-pomade-signer-rust format-pomade-signer-go

lint: lint-typescript lint-pomade-signer-rust lint-pomade-signer-go

build: build-typescript build-pomade-signer-rust build-pomade-signer-go

test: test-typescript test-pomade-signer-rust test-pomade-signer-go test-frost-taproot-rust test-frost-taproot-go
