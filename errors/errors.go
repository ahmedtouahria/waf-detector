package errors

import (
	"fmt"
)

// ErrorType represents the type of error
type ErrorType string

const (
	ErrorTypeNetwork    ErrorType = "NETWORK"
	ErrorTypeTimeout    ErrorType = "TIMEOUT"
	ErrorTypeInvalidURL ErrorType = "INVALID_URL"
	ErrorTypeParsing    ErrorType = "PARSING"
	ErrorTypeUnknown    ErrorType = "UNKNOWN"
)

// WAFError represents a custom error for WAF detection
type WAFError struct {
	Type    ErrorType
	URL     string
	Message string
	Err     error
}

func (e *WAFError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %s (%v)", e.Type, e.URL, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Type, e.URL, e.Message)
}

func (e *WAFError) Unwrap() error {
	return e.Err
}

// NewNetworkError creates a new network error
func NewNetworkError(url string, err error) *WAFError {
	return &WAFError{
		Type:    ErrorTypeNetwork,
		URL:     url,
		Message: "Network connection failed",
		Err:     err,
	}
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(url string) *WAFError {
	return &WAFError{
		Type:    ErrorTypeTimeout,
		URL:     url,
		Message: "Request timeout",
	}
}

// NewInvalidURLError creates a new invalid URL error
func NewInvalidURLError(url string, err error) *WAFError {
	return &WAFError{
		Type:    ErrorTypeInvalidURL,
		URL:     url,
		Message: "Invalid URL format",
		Err:     err,
	}
}

// NewParsingError creates a new parsing error
func NewParsingError(url string, err error) *WAFError {
	return &WAFError{
		Type:    ErrorTypeParsing,
		URL:     url,
		Message: "Failed to parse response",
		Err:     err,
	}
}

// NewUnknownError creates a new unknown error
func NewUnknownError(url string, err error) *WAFError {
	return &WAFError{
		Type:    ErrorTypeUnknown,
		URL:     url,
		Message: "Unknown error occurred",
		Err:     err,
	}
}
