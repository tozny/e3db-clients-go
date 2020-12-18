package request

import "net/http"

// Requester is a partial interface which allows decoration of the http Client
type Requester interface {
	Do(req *http.Request) (*http.Response, error)
}

// RequesterFunc is a function with acts as a Requester
type RequesterFunc func(*http.Request) (*http.Response, error)

// Do calls f(r)
func (f RequesterFunc) Do(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Interceptor is a function which decorates a Requester
//
// The interceptor can determine whether to pass the request down the line using
// the Do method, or perform some kind of operation on it, before or after it is
// sent. I could even short circuit the req, sending back a valid http Response,
// never calling the Do method on the next Requester.
type Interceptor func(Requester) Requester

// InterceptorFunc is an adapter to allow the use of ordinary functions as an
// Interceptor. If f is a function with the appropriate signature, InterceptorFunc(f)
// is an Interceptor that calls f.
func InterceptorFunc(f func(Requester, *http.Request) (*http.Response, error)) Interceptor {
	return func(c Requester) Requester {
		return RequesterFunc(func(r *http.Request) (*http.Response, error) {
			return f(c, r)
		})
	}
}

// ApplyInterceptors decorates a Requester with all passed Interceptors.
func ApplyInterceptors(requester Requester, interceptors ...Interceptor) Requester {
	for _, decorator := range interceptors {
		requester = decorator(requester)
	}
	return requester
}
