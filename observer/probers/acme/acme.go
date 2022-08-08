package probers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// ACMEProbe is the exported 'Prober' object for monitors configured to
// perform ACME requests.
type ACMEProbe struct {
	domains []string
	email   string
	keyType string
	url     string
}

// Name returns a string that uniquely identifies the monitor.
func (p ACMEProbe) Name() string {
	return fmt.Sprintf("%s-%s-%s", p.url, p.domains, p.keyType)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p ACMEProbe) Kind() string {
	return "ACME"
}

// MyUser implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// Probe performs the configured ACME request.
func (p ACMEProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	start := time.Now()

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, time.Since(start)
	}

	myUser := MyUser{
		Email: p.email,
		key:   privateKey,
	}

	// Create a new LEGO configuration from the probe configuration.
	config := lego.NewConfig(&myUser)
	config.CADirURL = p.url
	config.Certificate.KeyType = certcrypto.KeyType(p.keyType)

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return false, time.Since(start)
	}

	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	err = client.Challenge.SetHTTP01Provider(
		http01.NewProviderServer("", "5002"),
	)
	if err != nil {
		return false, time.Since(start)
	}
	err = client.Challenge.SetTLSALPN01Provider(
		tlsalpn01.NewProviderServer("", "5001"),
	)
	if err != nil {
		return false, time.Since(start)
	}

	// New users will need to register
	reg, err := client.Registration.Register(
		registration.RegisterOptions{TermsOfServiceAgreed: true},
	)
	if err != nil {
		return false, time.Since(start)
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: p.domains,
		Bundle:  true,
	}
	_, err = client.Certificate.Obtain(request)
	if err != nil {
		// this printf is for debugging purposes
		log.Printf("%s", err)
		return false, time.Since(start)
	}

	return true, time.Since(start)
}
