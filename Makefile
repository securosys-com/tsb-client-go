GO_MIN_TOOLCHAIN ?= go1.27.0
GO_PATCH_TOOLCHAIN ?= go1.27.1

.PHONY: check lint test govulncheck staticcheck nil-safety

check: lint test

lint: govulncheck staticcheck nil-safety

test:
	GOTOOLCHAIN=$(GO_MIN_TOOLCHAIN) go test -count=1 -v -timeout 20m ./...

govulncheck:
	GOTOOLCHAIN=$(GO_PATCH_TOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

staticcheck:
	GOTOOLCHAIN=$(GO_MIN_TOOLCHAIN) go run honnef.co/go/tools/cmd/staticcheck@2026.2rc1 $$(GOTOOLCHAIN=$(GO_MIN_TOOLCHAIN) go list ./...)

nil-safety:
	GOTOOLCHAIN=$(GO_MIN_TOOLCHAIN) go run go.uber.org/nilaway/cmd/nilaway@v0.0.0-20260803001828-dc48a6814e08 -test=false $$(GOTOOLCHAIN=$(GO_MIN_TOOLCHAIN) go list ./...)
