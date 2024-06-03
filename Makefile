build:
	@go build -o bin/ ./cmd/...
	
run:
	@go run cmd/awsec/main.go
