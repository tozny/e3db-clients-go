module github.com/tozny/e3db-clients-go

require (
	github.com/gbrlsnchs/jwt/v2 v2.0.0
	github.com/google/uuid v1.1.0
	github.com/gorilla/schema v1.4.1
	github.com/tozny/utils-go v0.0.51
	golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b
	golang.org/x/oauth2 v0.27.0
	gopkg.in/h2non/gentleman.v2 v2.0.5
)

require (
	github.com/nbio/st v0.0.0-20140626010706-e9e8d9816f32 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/net v0.0.0-20220722155237-a158d28d115b // indirect
	golang.org/x/sys v0.5.0 // indirect
)

replace golang.org/x/net => golang.org/x/net v0.7.0

replace golang.org/x/sys => golang.org/x/sys v0.0.0-20220412211240-33da011f77ad

go 1.23.0

toolchain go1.24.3
