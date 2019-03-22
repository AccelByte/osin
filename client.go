package osin

import (
	"github.com/AccelByte/go-jose/jwt"
	"strings"
)

// Client information
type Client interface {
	// Client id
	GetID() string

	// Client secret
	GetSecret() string

	// Base client uri
	GetRedirectURI() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

// ClientSecretMatcher is an optional interface clients can implement
// which allows them to be the one to determine if a secret matches.
// If a Client implements ClientSecretMatcher, the framework will never call GetSecret
type ClientSecretMatcher interface {
	// SecretMatches returns true if the given secret matches
	ClientSecretMatches(secret string) bool
}

type ClientIDMatcher interface {
	// ClientIDMatches returns true if the given ID matches
	ClientIDMatches(id string) bool
}

// DefaultClient stores all data in struct variables
type DefaultClient struct {
	Id          string
	Secret      string
	RedirectUri string
	UserData    interface{}
}

func (d *DefaultClient) GetID() string {
	return d.Id
}

func (d *DefaultClient) GetSecret() string {
	return d.Secret
}

func (d *DefaultClient) GetRedirectURI() string {
	return d.RedirectUri
}

func (d *DefaultClient) GetUserData() interface{} {
	return d.UserData
}

// ClientSecretMatches implement the ClientSecretMatcher interface
func (d *DefaultClient) ClientSecretMatches(secret string) bool {
	return d.Secret == secret
}

// ComboClient implements osin.Client interface
// This type of client is intended to handle multiple audience
// in the token
type ComboClient struct {
	Audience jwt.Audience
	Clients  []Client
}

// GetID satisfies osin.Client interface.
func (client *ComboClient) GetID() string {
	return strings.Join(client.Audience, ",")
}

// GetSecret satisfies osin.Client interface
func (client *ComboClient) GetSecret() string {
	secrets := make([]string, 0, len(client.Clients))
	for _, c := range client.Clients {
		secrets = append(secrets, c.GetSecret())
	}
	return strings.Join(secrets, ",")
}

// GetRedirectURI satisfies osin.Client interface
func (client *ComboClient) GetRedirectURI() string {
	uris := make([]string, 0, len(client.Clients))
	for _, c := range client.Clients {
		uris = append(uris, c.GetRedirectURI())
	}
	return strings.Join(uris, ",")
}

// GetUserData satisfies osin.Client interface
func (client *ComboClient) GetUserData() interface{} {
	data := make([]interface{}, 0, len(client.Clients))
	for _, c := range client.Clients {
		data = append(data, c.GetUserData())
	}
	return data
}

// ClientSecretMatches satisfies the ClientSecretMatcher interface
func (client *ComboClient) ClientSecretMatches(secret string) bool {
	return client.GetSecret() == secret
}

// ClientIDMatches satisfies the ClientIDMatcher interface
func (client *ComboClient) ClientIDMatches(id string) bool {
	return client.Audience.Contains(id)
}

func (d *DefaultClient) CopyFrom(client Client) {
	d.Id = client.GetID()
	d.Secret = client.GetSecret()
	d.RedirectUri = client.GetRedirectURI()
	d.UserData = client.GetUserData()
}
