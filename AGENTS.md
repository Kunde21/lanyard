# Agent Guidelines for Lanyard

Go OpenID Connect relying party library.

## Build/Test/Lint Commands

```bash
# Run all tests
go test ./...

# Run a single test
go test -run TestFunctionName ./path/to/package

# Run tests with coverage
go test -cover ./...

# Run tests with race detection
go test -race ./...

# Format code
gofumpt ./...

# Vet code for issues
go vet ./...

# Tidy dependencies
go mod tidy

# Download dependencies
go mod download

# Build the module
go build ./...

# Run specific package tests
go test ./pkg/oidc
```

## Dependencies

Add dependencies with:
```bash
go get github.com/some/package
```

## Code Style

### Imports
- Group imports: standard library, third-party, internal
- Use `goimports` for formatting
- Avoid dot imports
- Run `go mod tidy` after adding/removing imports

### Formatting
- Use `gofumpt` (enforced)
- Line length: aim for 100 chars, max 120
- Use tabs for indentation

### Naming Conventions
- Exported identifiers: PascalCase (e.g., `NewClient`)
- Unexported identifiers: camelCase (e.g., `parseToken`)
- Constants: PascalCase for exported, camelCase for unexported
- Interfaces: `-er` suffix when appropriate (e.g., `Reader`, `Handler`)
- Test functions: `Test` prefix (e.g., `TestNewClient`)
- Table-driven test cases: `tc` or `tt` for variable name

### Types
- Prefer explicit types over `interface{}`
- Use struct tags for JSON: `json:"field_name"`
- Return concrete types, accept interfaces
- Use pointer receivers for mutating methods

### Error Handling
- Always check errors: `if err != nil { return err }`
- Wrap errors with context: `fmt.Errorf("failed to X: %w", err)`
- Use sentinel errors for API boundaries
- Don't ignore errors with `_`

### Testing

**CRITICAL: Use `github.com/google/go-cmp/cmp` for assertions, NOT testify**

```go
import "github.com/google/go-cmp/cmp"

func TestFunction(t *testing.T) {
    got := Function()
    want := ExpectedValue
    if diff := cmp.Diff(want, got); diff != "" {
        t.Errorf("Function() mismatch (-want +got):\n%s", diff)
    }
}
```

For test options with cmp:
```go
cmpopts.IgnoreFields(MyStruct{}, "FieldToIgnore")
cmpopts.EquateErrors()
```

### Package Structure
- `cmd/` - command-line applications
- `pkg/` - public library code
- `internal/` - private implementation
- Keep packages focused and small

### Documentation
- All exported identifiers must have doc comments
- Comments start with the identifier name
- Example: `// Client represents an OIDC client.`

## Security
- Never log sensitive data (tokens, passwords)
- Use `crypto/rand` for security-sensitive randomness
- Validate all inputs
- Use constant-time comparison for secrets

## Common Tasks

Add go-cmp to test dependencies:
```bash
go get github.com/google/go-cmp/cmp
go get github.com/google/go-cmp/cmp/cmpopts
```

Run before committing:
```bash
gofumpt ./... && go vet ./... && go test ./...
```
