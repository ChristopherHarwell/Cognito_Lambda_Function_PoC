package main

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockCognitoClient is a mock implementation of the Cognito client
type MockCognitoClient struct {
	mock.Mock
}

func (m *MockCognitoClient) InitiateAuth(ctx context.Context, params *cognitoidentityprovider.InitiateAuthInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cognitoidentityprovider.InitiateAuthOutput), args.Error(1)
}

// TestClient is a wrapper to make the mock client compatible with the real client interface
type TestClient struct {
	*MockCognitoClient
}

func (t *TestClient) InitiateAuth(ctx context.Context, params *cognitoidentityprovider.InitiateAuthInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	return t.MockCognitoClient.InitiateAuth(ctx, params, optFns...)
}

func TestValidateEnvironment(t *testing.T) {
	// Save original values
	originalUserPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	originalClientID := os.Getenv("COGNITO_CLIENT_ID")
	defer func() {
		os.Setenv("COGNITO_USER_POOL_ID", originalUserPoolID)
		os.Setenv("COGNITO_CLIENT_ID", originalClientID)
	}()

	// Test case 1: Both environment variables are set
	os.Setenv("COGNITO_USER_POOL_ID", "test-pool")
	os.Setenv("COGNITO_CLIENT_ID", "test-client")
	valid, response := validateEnvironment()
	assert.True(t, valid)
	assert.Nil(t, response)

	// Test case 2: UserPoolID is missing
	os.Setenv("COGNITO_USER_POOL_ID", "")
	valid, response = validateEnvironment()
	assert.False(t, valid)
	assert.NotNil(t, response)
	assert.Equal(t, 500, response.StatusCode)

	// Test case 3: ClientID is missing
	os.Setenv("COGNITO_USER_POOL_ID", "test-pool")
	os.Setenv("COGNITO_CLIENT_ID", "")
	valid, response = validateEnvironment()
	assert.False(t, valid)
	assert.NotNil(t, response)
	assert.Equal(t, 500, response.StatusCode)
}

func TestValidateInput_ValidCredentials(t *testing.T) {
	randomValidPassword, _ := GenerateRandomString(8, 128)
	request := Request{
		Username: "testuser",
		Password: randomValidPassword,
	}
	valid, response := validateInput(request)
	assert.True(t, valid)
	assert.Nil(t, response)
}

func TestValidateInput_MissingUsername(t *testing.T) {
	randomValidPassword, _ := GenerateRandomString(8, 128)
	request := Request{
		Username: "",
		Password: randomValidPassword,
	}
	valid, response := validateInput(request)
	assert.False(t, valid)
	assert.NotNil(t, response)
	assert.Equal(t, 400, response.StatusCode)
}

func TestValidateInput_MissingPassword(t *testing.T) {
	request := Request{
		Username: "testuser",
		Password: "",
	}
	valid, response := validateInput(request)
	assert.False(t, valid)
	assert.NotNil(t, response)
	assert.Equal(t, 400, response.StatusCode)
}

func TestValidateInput_UsernameTooLong(t *testing.T) {
	randomValidPassword, _ := GenerateRandomString(8, 128)
	request := Request{
		Username: "this-is-a-very-long-username-that-exceeds-the-maximum-length-allowed-by-cognito",
		Password: randomValidPassword,
	}
	valid, response := validateInput(request)
	assert.False(t, valid)
	assert.NotNil(t, response)
	assert.Equal(t, 400, response.StatusCode)
}

func TestValidateInput_PasswordTooLong(t *testing.T) {
	randomInvalidPassword, _ := GenerateRandomString(129, 200)
	request := Request{
		Username: "testuser",
		Password: randomInvalidPassword,
	}
	valid, response := validateInput(request)
	assert.False(t, valid)
	assert.NotNil(t, response)
	assert.Equal(t, 400, response.StatusCode)
}

func TestValidateInput_UsernameTooShort(t *testing.T) {
	randomValidPassword, _ := GenerateRandomString(8, 128)
	request := Request{
		Username: "a",
		Password: randomValidPassword,
	}
	valid, response := validateInput(request)
	assert.False(t, valid)
	assert.NotNil(t, response)
	assert.Equal(t, 400, response.StatusCode)
}

func TestValidateInput_PasswordTooShort(t *testing.T) {
	request := Request{
		Username: "testuser",
		Password: "short",
	}
	valid, response := validateInput(request)
	assert.False(t, valid)
	assert.NotNil(t, response)
	assert.Equal(t, 400, response.StatusCode)
}

func TestValidateInput_UsernameWithSpecialCharacters(t *testing.T) {
	randomValidPassword, _ := GenerateRandomString(8, 128)
	request := Request{
		Username: "user@example.com",
		Password: randomValidPassword,
	}
	valid, response := validateInput(request)
	assert.True(t, valid)
	assert.Nil(t, response)
}

func TestValidateInput_PasswordWithSpecialCharacters(t *testing.T) {
	request := Request{
		Username: "testuser",
		Password: "special@123",
	}
	valid, response := validateInput(request)
	assert.True(t, valid)
	assert.Nil(t, response)
}

func TestPrepareAuthInput(t *testing.T) {
	// Save original value
	originalClientID := os.Getenv("COGNITO_CLIENT_ID")
	os.Setenv("COGNITO_CLIENT_ID", "test-client")
	defer func() {
		os.Setenv("COGNITO_CLIENT_ID", originalClientID)
	}()

	request := Request{
		Username: "testuser",
		Password: "testpass",
	}

	authInput := prepareAuthInput(request)

	assert.Equal(t, types.AuthFlowTypeUserPasswordAuth, authInput.AuthFlow)
	assert.Equal(t, "test-client", *authInput.ClientId)
	assert.Equal(t, "testuser", authInput.AuthParameters["USERNAME"])
	assert.Equal(t, "testpass", authInput.AuthParameters["PASSWORD"])
}

func TestAttemptAuthentication(t *testing.T) {
	ctx := context.Background()
	mockClient := &TestClient{new(MockCognitoClient)}
	authInput := &cognitoidentityprovider.InitiateAuthInput{}

	// Test case 1: Successful authentication
	expectedOutput := &cognitoidentityprovider.InitiateAuthOutput{
		AuthenticationResult: &types.AuthenticationResultType{
			AccessToken:  stringPtr("access-token"),
			IdToken:      stringPtr("id-token"),
			RefreshToken: stringPtr("refresh-token"),
			ExpiresIn:    3600,
		},
	}
	mockClient.Mock.On("InitiateAuth", ctx, authInput).Return(expectedOutput, nil)

	result, response := attemptAuthentication(ctx, mockClient, authInput)
	assert.NotNil(t, result)
	assert.Nil(t, response)
	assert.Equal(t, "access-token", *result.AuthenticationResult.AccessToken)

	// Test case 2: Not authorized
	mockClient = &TestClient{new(MockCognitoClient)}
	mockClient.Mock.On("InitiateAuth", ctx, authInput).Return(nil, &types.NotAuthorizedException{})
	result, response = attemptAuthentication(ctx, mockClient, authInput)
	assert.Nil(t, result)
	assert.NotNil(t, response)
	assert.Equal(t, 401, response.StatusCode)

	// Test case 3: User not found
	mockClient = &TestClient{new(MockCognitoClient)}
	mockClient.Mock.On("InitiateAuth", ctx, authInput).Return(nil, &types.UserNotFoundException{})
	result, response = attemptAuthentication(ctx, mockClient, authInput)
	assert.Nil(t, result)
	assert.NotNil(t, response)
	assert.Equal(t, 404, response.StatusCode)
}

func TestHandleRequest(t *testing.T) {
	ctx := context.Background()

	// Save original values
	originalUserPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	originalClientID := os.Getenv("COGNITO_CLIENT_ID")
	defer func() {
		os.Setenv("COGNITO_USER_POOL_ID", originalUserPoolID)
		os.Setenv("COGNITO_CLIENT_ID", originalClientID)
	}()

	// Set up environment variables
	os.Setenv("COGNITO_USER_POOL_ID", "test-pool")
	os.Setenv("COGNITO_CLIENT_ID", "test-client")

	// Test case 1: Successful authentication
	mockClient := &TestClient{new(MockCognitoClient)}
	expectedOutput := &cognitoidentityprovider.InitiateAuthOutput{
		AuthenticationResult: &types.AuthenticationResultType{
			AccessToken:  stringPtr("access-token"),
			IdToken:      stringPtr("id-token"),
			RefreshToken: stringPtr("refresh-token"),
			ExpiresIn:    3600,
		},
	}
	mockClient.Mock.On("InitiateAuth", ctx, mock.Anything).Return(expectedOutput, nil)

	request := Request{
		Username: "testuser",
		Password: "testpass",
	}

	response, err := HandleRequest(ctx, request, mockClient)
	assert.Nil(t, err)
	assert.Equal(t, 200, response.StatusCode)
	authResponse := response.Body.(AuthResponse)
	assert.Equal(t, "access-token", authResponse.AccessToken)
	assert.Equal(t, "id-token", authResponse.IDToken)
	assert.Equal(t, "refresh-token", authResponse.RefreshToken)
	assert.Equal(t, int32(3600), authResponse.ExpiresIn)

	// Test case 2: Invalid input
	request.Username = ""
	response, err = HandleRequest(ctx, request, mockClient)
	assert.Nil(t, err)
	assert.Equal(t, 400, response.StatusCode)
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
