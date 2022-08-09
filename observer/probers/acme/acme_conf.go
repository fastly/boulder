package probers

import (
	"fmt"
	"net/url"

	"github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v2"
)

// ACMEConf is exported to receive YAML configuration.
type ACMEConf struct {
	Domains []string `yaml:"domains"`
	Email   string   `yaml:"email"`
	KeyType string   `yaml:"keytype"`
	URL     string   `yaml:"url"`
}

// UnmarshalSettings takes YAML as bytes and unmarshals it to an
// ACMEConf object.
func (c ACMEConf) UnmarshalSettings(settings []byte) (probers.Configurer, error) {
	var conf ACMEConf
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func (c ACMEConf) validateURL() error {
	url, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf(
			"invalid 'url', got: %q, expected a valid url", c.URL)
	}
	if url.Scheme == "" {
		return fmt.Errorf(
			"invalid 'url', got: %q, missing scheme", c.URL)
	}
	return nil
}

func (c ACMEConf) validateKeyType() error {
	switch c.KeyType {
	case "":
		return nil
	case "P256":
		return nil
	case "P384":
		return nil
	case "2048":
		return nil
	case "4096":
		return nil
	case "8192":
		return nil
	default:
		return fmt.Errorf(
			"invalid 'keytype', got: %q, expected '2048','4096','8192','P256' or 'P384'", c.KeyType)
	}
}

// MakeProber constructs an `ACMEProbe` object from the contents of the
// bound `ACMEConf` object. If the `ACMEConf` cannot be validated, an
// error appropriate for end-user consumption is returned instead.
func (c ACMEConf) MakeProber() (probers.Prober, error) {
	// validate `keyType`
	err := c.validateKeyType()
	if err != nil {
		return nil, err
	}

	// validate `url`
	err = c.validateURL()
	if err != nil {
		return nil, err
	}

	prefixLength := 2
	return ACMEProbe{
		c.Domains, c.Email, c.KeyType, prefixLength, c.URL}, nil
}

// init is called at runtime and registers `ACMEConf`, a `Prober`
// `Configurer` type, as "ACME".
func init() {
	probers.Register("ACME", ACMEConf{})
}
