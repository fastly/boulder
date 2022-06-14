package probers

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/letsencrypt/boulder/test"
	"gopkg.in/yaml.v2"
)

func TestACMEConf_MakeProber(t *testing.T) {
	type fields struct {
		CADirURL string
		Domain   string
		Email    string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid server valid domain valid email", fields{"https://api.example.com/directory", "example.net", "nobody@example.com"}, false},
		// invalid
		{"missing scheme", fields{"api.example.com", "example.net", "nobody@example.com"}, true},
		{"bad server valid domain valid email", fields{"https://api.example", "example.net", "nobody@example.org"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ACMEConf{
				CADirURL: tt.fields.CADirURL,
				Domain:   tt.fields.Domain,
				Email:    tt.fields.Email,
			}
			if _, err := c.MakeProber(); (err != nil) != tt.wantErr {
				t.Errorf("ACMEConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestACMEConf_UnmarshalSettings(t *testing.T) {
	type fields struct {
		caDirURL interface{}
		domain   interface{}
		email    interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    probers.Configurer
		wantErr bool
	}{
		{"valid", fields{"https://api.example.com/directory", "example.net", "nobody@example.org"},
			ACMEConf{"https://api.example.com/directory", "example.net", "nobody@example.org"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := probers.Settings{
				"caDirURL": tt.fields.caDirURL,
				"domain":   tt.fields.domain,
				"email":    tt.fields.email,
			}
			settingsBytes, _ := yaml.Marshal(settings)
			c := ACMEConf{}
			got, err := c.UnmarshalSettings(settingsBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("DNSConf.UnmarshalSettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DNSConf.UnmarshalSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACMEProberName(t *testing.T) {
	proberYAML := `
caDirURL: https://api.example.com/directory
domain: example.net
email: nobody@example.org
`
	c := ACMEConf{}
	configurer, err := c.UnmarshalSettings([]byte(proberYAML))
	test.AssertNotError(t, err, "Got error for valid prober config")
	prober, err := configurer.MakeProber()
	test.AssertNotError(t, err, "Got error for valid prober config")
	test.AssertEquals(t, prober.Name(), "https://api.example.com/directory-example.net-nobody@example.org")

}
