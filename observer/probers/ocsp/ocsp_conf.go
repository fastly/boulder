package probers

import (
	"fmt"
	"net/url"

	"github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v2"
)

// ACMEConf is exported to receive YAML configuration.
type ACMEConf struct {
	CADirURL string `yaml:"caDirURL"`
	Domain   string `yaml:"domain"`
	Email    string `yaml:"email"`
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
	url, err := url.Parse(c.CADirURL)
	if err != nil {
		return fmt.Errorf(
			"invalid 'caDirURL', got: %q, expected a valid url", c.CADirURL)
	}
	if url.Scheme == "" {
		return fmt.Errorf(
			"invalid 'caDirURL', got: %q, missing scheme", c.CADirURL)
	}
	return nil
}

// MakeProber constructs an `ACMEProbe` object from the contents of the
// bound `ACMEConf` object. If the `ACMEConf` cannot be validated, an
// error appropriate for end-user consumption is returned instead.
func (c ACMEConf) MakeProber() (probers.Prober, error) {
	// validate `caDirURL`
	err := c.validateURL()
	if err != nil {
		return nil, err
	}

	return ACMEProbe{c.CADirURL, c.Domain, c.Email}, nil
}

// init is called at runtime and registers `ACMEConf`, a `Prober`
// `Configurer` type, as "ACME".
func init() {
	probers.Register("ACME", ACMEConf{})
}
