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
		Domain  string
		Email   string
		KeyType string
		URL     string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid domain valid email valid ec keytype valid url", fields{"example.net", "nobody@example.com", "P256", "https://api.example.com/directory"}, false},
		{"valid domain valid email valid rsa keytype valid url", fields{"example.net", "nobody@example.com", "4096", "https://api.example.com/directory"}, false},
		// invalid
		{"url missing scheme", fields{"example.net", "nobody@example.com", "P256", "api.example.com"}, true},
		{"valid domain valid email valid keytype bad url", fields{"example.net", "nobody@example.org", "P256", "https://api.example"}, false},
		{"valid domain valid email bad keytype valid url", fields{"example.net", "nobody@example.org", "1024", "https://api.example.com/directory"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ACMEConf{
				Domain:  tt.fields.Domain,
				Email:   tt.fields.Email,
				KeyType: tt.fields.KeyType,
				URL:     tt.fields.URL,
			}
			if _, err := c.MakeProber(); (err != nil) != tt.wantErr {
				t.Errorf("ACMEConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestACMEConf_UnmarshalSettings(t *testing.T) {
	type fields struct {
		domain  interface{}
		email   interface{}
		keyType interface{}
		url     interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    probers.Configurer
		wantErr bool
	}{
		{"valid", fields{"example.net", "nobody@example.org", "P256", "https://api.example.com/directory"},
			ACMEConf{"example.net", "nobody@example.org", "P256", "https://api.example.com/directory"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := probers.Settings{
				"domain":  tt.fields.domain,
				"email":   tt.fields.email,
				"keytype": tt.fields.keyType,
				"url":     tt.fields.url,
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
domain: example.net
email: nobody@example.org
keytype: P256
url: https://api.example.com/directory
`
	c := ACMEConf{}
	configurer, err := c.UnmarshalSettings([]byte(proberYAML))
	test.AssertNotError(t, err, "Got error for valid prober config")
	prober, err := configurer.MakeProber()
	test.AssertNotError(t, err, "Got error for valid prober config")
	test.AssertEquals(t, prober.Name(), "https://api.example.com/directory-example.net-P256")
}
