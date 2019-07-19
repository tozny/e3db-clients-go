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
Export valid values for use by the integration tests

```
export E3DB_API_URL=http://platform.local.tozny.com
export E3DB_AUTH_SERVICE_HOST=http://platform.local.tozny.com:8003
export E3DB_ACCOUNT_SERVICE_HOST=http://platform.local.tozny.com:8002
export E3DB_STORAGE_SERVICE_HOST=http://platform.local.tozny.com:8001
export E3DB_CLIENT_SERVICE_HOST=http://platform.local.tozny.com:8003
export E3DB_HOOK_SERVICE_HOST=http://platform.local.tozny.com:8006
export E3DB_SEARCH_INDEXER_HOST=http://platform.local.tozny.com:9010
export E3DB_IDENTITY_SERVICE_HOST=http://platform.local.tozny.com:8009
export E3DB_API_KEY_ID=1d66c182779e47714cd957d4760a121580598d68e064c948e5887662c197538b
export E3DB_API_KEY_SECRET=aaadbd1cc72870e6bd41befa1273b4513d0d1fa04fb913257eec6158b6a35d75
export E3DB_CLIENT_ID=864e4b87-9eda-43fb-ae6d-d07d4275c73a
export WEBHOOK_URL=https://en8781lpip6xb.x.pipedream.net/
```
Then run:
```
make test
```
to execute integration tests using the code in this project to make API calls against the specified e3db instance.

Sample values above will work against running local services from checked out [pds-service](https://github.com/tozny/pds-service) and [e3dbSearchService](https://github.com/tozny/e3dbSearchService) repos.

## Use

From a go package

```go
package main

import (
    "github.com/tozny/e3db-clients-go"
    "github.com/tozny/e3db-clients-go/hookClient"
    "context"
)

func main() {
    config := e3dbClients.ClientConfig{
        APIKey:    "E3DBAPIKEYID",
        APISecret: "E3DBAPIKEYSECRET",
        Host:      "https://api.e3db.com",
    }
    client := hookClient.New(ValidClientConfig, config.Host)
    createHookRequest := hookClient.CreateHookRequest{
        WebhookURL: "https://en8781lpip6xb.x.pipedream.net/",
        Triggers: []hookClient.HookTrigger{
            hookClient.HookTrigger{
                Enabled:  true,
                APIEvent: "authorizer_added",
            },
        },
    }
    ctx := context.TODO()
    response, err := client.CreateHook(ctx, createHookRequest)
    if err != nil {
        t.Errorf("Error %s calling CreateHook with %+v\n", err, createHookRequest)
    }
}
```

