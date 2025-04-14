package main

import (
	"context"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

// CognitoClient interface for mocking in tests
type CognitoClient interface {
	InitiateAuth(ctx context.Context, params *cognitoidentityprovider.InitiateAuthInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.InitiateAuthOutput, error)
}

// Request represents the incoming Lambda request structure
type Request struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Response represents the Lambda response structure
type Response struct {
	StatusCode int         `json:"statusCode"`
	Body       interface{} `json:"body"`
}

// AuthResponse represents the successful authentication response
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int32  `json:"expires_in"`
}

// ErrorResponse represents the error response structure
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// validateEnvironment checks if required environment variables are set
func validateEnvironment() (bool, *Response) {
	userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	clientID := os.Getenv("COGNITO_CLIENT_ID")

	if userPoolID == "" || clientID == "" {
		return false, &Response{
			StatusCode: 500,
			Body: ErrorResponse{
				Error:   "ConfigurationError",
				Message: "Missing required environment variables",
			},
		}
	}
	return true, nil
}

func validateUsername(username string) (bool, *Response) {
	if username == "" {
		return false, &Response{
			StatusCode: 400,
			Body: ErrorResponse{
				Error:   "ValidationError",
				Message: "Username is required",
			},
		}
	}
	if len(username) < 3 {
		return false, &Response{
			StatusCode: 400,
			Body: ErrorResponse{
				Error:   "ValidationError",
				Message: "Username must be at least 3 characters",
			},
		}
	}
	if len(username) > 20 {
		return false, &Response{
			StatusCode: 400,
			Body: ErrorResponse{
				Error:   "ValidationError",
				Message: "Username must be less than 20 characters",
			},
		}
	}
	return true, nil
}

func validatePassword(password string) (bool, *Response) {
	if password == "" {
		return false, &Response{
			StatusCode: 400,
			Body: ErrorResponse{
				Error:   "ValidationError",
				Message: "Password is required",
			},
		}
	}
	if len(password) < 8 || len(password) > 128 {
		return false, &Response{
			StatusCode: 400,
			Body: ErrorResponse{
				Error:   "ValidationError",
				Message: "Password must be between 8 and 128 characters",
			},
		}
	}
	return true, nil
}

// validateInput checks if the required request fields are present
func validateInput(request Request) (bool, *Response) {
	if _, ok := handleValidationStep(validateUsername(request.Username)); !ok {
		return false, &Response{
			StatusCode: 400,
			Body: ErrorResponse{
				Error:   "ValidationError",
				Message: "Username must be less than 20 characters",
			},
		}
	}
	if _, ok := handleValidationStep(validatePassword(request.Password)); !ok {
		return false, &Response{
			StatusCode: 400,
			Body: ErrorResponse{
				Error:   "ValidationError",
				Message: "Password must be between 8 and 128 characters",
			},
		}
	}

	return true, nil
}

// prepareAuthInput creates the authentication input parameters
func prepareAuthInput(request Request) *cognitoidentityprovider.InitiateAuthInput {
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	return &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: &clientID,
		AuthParameters: map[string]string{
			"USERNAME": request.Username,
			"PASSWORD": request.Password,
		},
	}
}

// attemptAuthentication tries to authenticate the user with Cognito
func attemptAuthentication(ctx context.Context, client CognitoClient, authInput *cognitoidentityprovider.InitiateAuthInput) (*cognitoidentityprovider.InitiateAuthOutput, *Response) {
	result, err := client.InitiateAuth(ctx, authInput)
	if err != nil {
		var message string
		var statusCode int

		switch err.(type) {
		case *types.NotAuthorizedException:
			statusCode = 401
			message = "Invalid username or password"
		case *types.UserNotFoundException:
			statusCode = 404
			message = "User not found"
		case *types.UserNotConfirmedException:
			statusCode = 403
			message = "User is not confirmed"
		case *types.PasswordResetRequiredException:
			statusCode = 403
			message = "Password reset required"
		default:
			statusCode = 500
			message = "An internal error occurred"
		}

		return nil, &Response{
			StatusCode: statusCode,
			Body: ErrorResponse{
				Error:   "AuthenticationError",
				Message: message,
			},
		}
	}

	return result, nil
}

// handleValidationStep executes a validation step and returns the appropriate response if validation fails
func handleValidationStep(valid bool, errResponse *Response) (*Response, bool) {
	if !valid {
		return errResponse, false
	}
	return nil, true
}

// loadAWSConfig loads the AWS configuration and creates a Cognito client
func loadAWSConfig(ctx context.Context) (CognitoClient, *Response) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, &Response{
			StatusCode: 500,
			Body: ErrorResponse{
				Error:   "ConfigurationError",
				Message: "Failed to load AWS configuration",
			},
		}
	}

	// Create Cognito client
	client := cognitoidentityprovider.NewFromConfig(cfg)
	return client, nil
}

// HandleRequest processes the authentication request
func HandleRequest(ctx context.Context, request Request, client CognitoClient) (Response, error) {
	// Execute validation steps in sequence
	if response, ok := handleValidationStep(validateEnvironment()); !ok {
		return *response, nil
	}

	if response, ok := handleValidationStep(validateInput(request)); !ok {
		return *response, nil
	}

	// If no client provided, create one
	if client == nil {
		var errResponse *Response
		client, errResponse = loadAWSConfig(ctx)
		if errResponse != nil {
			return *errResponse, nil
		}
	}

	// Prepare and attempt authentication
	authInput := prepareAuthInput(request)
	result, errResponse := attemptAuthentication(ctx, client, authInput)
	if errResponse != nil {
		return *errResponse, nil
	}

	// Return successful response with tokens
	return Response{
		StatusCode: 200,
		Body: AuthResponse{
			AccessToken:  *result.AuthenticationResult.AccessToken,
			IDToken:      *result.AuthenticationResult.IdToken,
			RefreshToken: *result.AuthenticationResult.RefreshToken,
			ExpiresIn:    result.AuthenticationResult.ExpiresIn,
		},
	}, nil
}

func main() {
	lambda.Start(func(ctx context.Context, request Request) (Response, error) {
		return HandleRequest(ctx, request, nil)
	})
}
