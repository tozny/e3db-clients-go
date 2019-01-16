# e3db-clients-go
Contains golang implementations of http clients for use by golang applications that need to interface with e3db services.

## Pre-requisites
* Go 1.11+ must be installed, follow [these instructions ](https://golang.org/doc/install) if not installed in your development environment.

## Build
Running:
```
make build
```
will lint and build the projects source code.

## Test
Export valid values for use by the integration tests:
```
export E3DB_API_URL=https://dev.e3db.com
export E3DB_API_KEY_ID=6f159d70096cedd0cadc9fb8f9e2a5e15d48e432a3ebfa2458e7788bc0684a99
export E3DB_API_KEY_SECRET=2acf80b5707db78f477670f70c06a8a8888a507cc10aadc0ee4122166bd5649a
export E3DB_CLIENT_ID=864e4b87-9eda-43fb-ae6d-d07d4275c73a
```
* Recommend to use credentials and endpoint of dev
* Go to http://console.dev.tozny.com
* Click create account and fill in information
* Once logged into the console, create a client and use the values of `api_secret` and `api_key_id`

Then run:
```
make test
```
to execute integration tests using the code in this project to make API calls against the specified e3db instance.

## Use

From a go package

```go
package main

import (
    "github.com/tozny/e3db-clients-go"
    "github.com/tozny/e3db-clients-go/authClient"
    "context"
)

func main() {
    config := e3dbClients.ClientConfig{
        APIKey:    "E3DBAPIKEYID",
        APISecret: "E3DBAPIKEYSECRET",
        Host:      "https://api.e3db.com",
    }
    e3dbAuth := authClient.New(config)
    ctx := context.Background()
    token, err := e3dbAuth.GetToken(ctx)
    if err != nil {
        panic(err)
    }
    //Use token to make authenticated calls to other
    //e3db services, renewing as needed
}
```

