package request

import (
	"net/http"

	"github.com/tozny/utils-go/logging"
	"golang.org/x/oauth2"
)

// ApplyTokenInterceptor adds an Authorization token from an oauth2 source to a
// request as part of an interceptor.
func ApplyTokenInterceptor(s oauth2.TokenSource) Interceptor {
	return InterceptorFunc(func(c Requester, r *http.Request) (*http.Response, error) {
		token, err := s.Token()
		if err != nil {
			return nil, err
		}
		token.SetAuthHeader(r)
		return c.Do(r)
	})
}

// LoggingInterceptor logs out request details when a logger in debug mode is supplied
func LoggingInterceptor(l logging.Logger) Interceptor {
	return InterceptorFunc(func(c Requester, r *http.Request) (*http.Response, error) {
		l.Debugf("Making request to %s", r.URL)
		return c.Do(r)
	})
}
