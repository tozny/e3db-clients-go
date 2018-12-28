# e3db-clients-go
Contains golang implementations of http clients for interacting with e3db services.

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
```
* Recommend to run against dev for safety reasons
* You can get values for the api key and secret by registering a client with the instance of e3db specified by E3DB_API_URL, or if testing against dev run the command below to retrieve a valid api key id and secret for use.
    ```
    credstash -t dev-e3db get  dev_e3db_api_key_id

    credstash -t dev-e3db get  dev_e3db_api_secret
    ```

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
    "github.com/tozny/e3db-clients-go/authClient"
    "context"
)

func main() {
    e3dbAuth := authClient.New("E3DBAPIKEYID", "E3DBAPIKEYSECRET")
    ctx := context.Background()
    token, err := e3dbAuth.GetToken(ctx)
    if err != nil {
        panic(err)
    }
    //Use token to make authenticated calls to e3db services
    //e3db services, renewing as needed
}
```

