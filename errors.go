package hibp

import (
	"fmt"
	"net/http"
)

// ErrorUnexpectedResponse is an error returned if the response from the
// HaveIBeenPwned.org API was not expected.
type ErrorUnexpectedResponse struct {
	// Response that was not expected.
	Response *http.Response
}

func (e *ErrorUnexpectedResponse) Error() string {
	return fmt.Sprintf("hibp: Unexpected HTTP Response %q from %s %q", e.Response.Status, e.Response.Request.Method, e.Response.Request.URL.String())
}
