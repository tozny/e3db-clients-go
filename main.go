package e3dbClients

import ()

// ClientConfig wraps configuration
// needed by an e3db client
type ClientConfig struct {
    Host      string //Hostname of the e3db API to communicate with
    APIKey    string //User/Client ID to use when communicating with the e3db API
    APISecret string //User/Client secret to use when communicating with the e3db API
}
