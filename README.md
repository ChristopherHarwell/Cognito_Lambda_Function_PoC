# AWS Cognito Lambda Authentication

This project implements an AWS Lambda function in Go that handles user authentication using AWS Cognito. The function processes login requests and returns JWT tokens upon successful authentication.

## Features

- User authentication using AWS Cognito User Pools
- JWT token generation and handling
- Error handling for various authentication scenarios
- Secure credential management

## Prerequisites

- Go 1.21 or later
- AWS Account with Cognito User Pool configured
- AWS CLI configured with appropriate credentials

## Environment Variables

The following environment variables need to be set in your Lambda function:

- `COGNITO_USER_POOL_ID`: The ID of your Cognito User Pool
- `COGNITO_CLIENT_ID`: The client ID of your Cognito App Client

## Project Structure

```
.
├── README.md
├── go.mod
├── go.sum
├── main.go
└── docs/
    └── cognito_lambda_design.md
```

## Building and Deployment

1. Build the Lambda function:
   ```bash
   GOOS=linux GOARCH=amd64 go build -o main
   ```

2. Create a ZIP file containing the binary:
   ```bash
   zip function.zip main
   ```

3. Deploy to AWS Lambda using AWS CLI:
   ```bash
   aws lambda create-function \
     --function-name cognito-auth \
     --runtime provided.al2 \
     --handler main \
     --zip-file fileb://function.zip \
     --role YOUR_LAMBDA_ROLE_ARN
   ```

## API Request Format

```json
{
    "username": "user@example.com",
    "password": "userPassword123"
}
```

## API Response Format

### Success Response
```json
{
    "statusCode": 200,
    "body": {
        "access_token": "eyJ...",
        "id_token": "eyJ...",
        "refresh_token": "eyJ...",
        "expires_in": 3600
    }
}
```

### Error Response
```json
{
    "statusCode": 401,
    "body": {
        "error": "AuthenticationError",
        "message": "Invalid username or password"
    }
}
```

## Security Considerations

- All sensitive information is handled through environment variables
- No credentials are logged or stored
- JWT tokens are securely transmitted
- Error messages are sanitized to prevent information leakage

## License

MIT License 