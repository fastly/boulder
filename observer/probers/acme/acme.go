package probers

// DONE: add random prefix to first domain name in domains list
// TODO: add dns challenge and internal dns server with challenge solver

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
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/letsencrypt/challtestsrv"
)

// ACMEProbe is the exported 'Prober' object for monitors configured to
// perform ACME requests.
type ACMEProbe struct {
	domains      []string
	email        string
	keyType      string
	prefixLength int
	url          string
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
		return false, 0
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
		return false, 0
	}

	challSrvDNS, err := NewDNSProviderChallSrv()
	// challSrvDNS, err := dns01.NewDNSProviderManual()
	if err != nil {
		return false, 0
	}
	err = client.Challenge.SetDNS01Provider(challSrvDNS)
	if err != nil {
		return false, 0
	}

	// New users will need to register
	reg, err := client.Registration.Register(
		registration.RegisterOptions{TermsOfServiceAgreed: true},
	)
	if err != nil {
		return false, 0
	}
	myUser.Registration = reg

	var myDomains = make([]string, len(p.domains))
	copy(myDomains, p.domains)
	if p.prefixLength > 0 {
		// Add a random prefix to the first domain name in the list.
		myDomains[0] = fmt.Sprintf("%s.%s", randString(p.prefixLength), p.domains[0])
	}

	request := certificate.ObtainRequest{
		Domains: myDomains,
		Bundle:  true,
	}
	_, err = client.Certificate.Obtain(request)
	if err != nil {
		// this printf is for debugging purposes
		log.Printf("%s", err)
		return false, 0
	}

	return true, time.Since(start)
}

func randString(n int) string {
	// Random string of length n
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

var challSrv *challtestsrv.ChallSrv

type DNSProviderChallSrv struct{}

func NewDNSProviderChallSrv() (*DNSProviderChallSrv, error) {
	// Nothing to do if challtestsrv is already running.
	if challSrv != nil {
		return &DNSProviderChallSrv{}, nil
	}

	// Create and start challtestsrv.
	var err error
	challSrv, err = challtestsrv.New(challtestsrv.Config{DNSOneAddrs: []string{":5053"}})
	if err != nil {
		return nil, err
	}
	go challSrv.Run()

	return &DNSProviderChallSrv{}, nil
}

func (d *DNSProviderChallSrv) Present(domain, token, _ string) error {
	log.Printf("Presenting domain %s with token %s", domain, token)

	challengeDomain := fmt.Sprintf("_acme-challenge.%s", domain)
	challSrv.AddDNSOneChallenge(challengeDomain, token)

	return nil
}

func (d *DNSProviderChallSrv) CleanUp(domain, _, _ string) error {
	challSrv.DeleteDNSOneChallenge(domain)
	return nil
}
