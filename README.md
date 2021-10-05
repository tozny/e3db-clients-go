# Disclaimer: This is an internal library and should not be relied upon for production uses by non-Toznynians

# e3db-clients-go

Contains golang implementations of http clients for use by golang applications that need to interface with e3db services.

## Pre-requisites

* Go 1.11+ must be installed, follow [these instructions ](https://golang.org/doc/install) if not installed in your development environment.

* [Tozny Platform](https://github.com/tozny/tozny-platform) checked out locally

    1. `TOZNY_PLATFORM_DIR` environment set pointing to the repo ☝️

    2. OR: Alternate configuration values in [`.env`](./env) for the Tozny services and clients of choice

## Build

Running:

```bash
make build
```

will lint and build the projects source code.

## Test

Project tests run against an instance of Tozny Platform.

To run Tozny Platform services

```bash
make up
```

After Tozny Platform is up, execute the tests by running:

```bash
make test
```

To Run tests matching the name in 'method' form:

```bash
make testone method=TestCreateCustomer
```


After testing is done, you can stop Tozny Platform services by running

```bash
make down
```

## Use

From a go package

```go
package main

import (
	"context"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/hookClient"
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

## Publishing

Follow [semantic versioning](https://semver.org) when releasing new versions of this library.

Releasing involves tagging a commit in this repository, and pushing the tag. Tagging and releasing of new versions should only be done from the master branch after an approved Pull Request has been merged, or on the branch of an approved Pull Request.

To publish a new version, run

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

To consume published updates from other repositories that depends on this module run

```bash
go get github.com/tozny/e3db-clients-go@vX.Y.Z
```

and the go `get` tool will fetch the published artifact and update that modules `go.mod` and`go.sum` files with the updated dependency.
