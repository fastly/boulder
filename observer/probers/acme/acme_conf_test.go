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
		Email    string
		CADirURL string
		Domain   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid fqdn valid rcode", fields{"http://example.com", []int{200}}, false},
		{"valid hostname valid rcode", fields{"example", []int{200}}, true},
		// invalid
		{"valid fqdn no rcode", fields{"http://example.com", nil}, true},
		{"valid fqdn invalid rcode", fields{"http://example.com", []int{1000}}, true},
		{"valid fqdn 1 invalid rcode", fields{"http://example.com", []int{200, 1000}}, true},
		{"bad fqdn good rcode", fields{":::::", []int{200}}, true},
		{"missing scheme", fields{"example.com", []int{200}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ACMEConf{
				URL:    tt.fields.URL,
				RCodes: tt.fields.RCodes,
			}
			if _, err := c.MakeProber(); (err != nil) != tt.wantErr {
				t.Errorf("ACMEConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestACMEConf_UnmarshalSettings(t *testing.T) {
	type fields struct {
		url       interface{}
		rcodes    interface{}
		useragent interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    probers.Configurer
		wantErr bool
	}{
		{"valid", fields{"google.com", []int{200}, "boulder_observer"}, ACMEConf{"google.com", []int{200}, "boulder_observer"}, false},
		{"invalid", fields{42, 42, 42}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := probers.Settings{
				"url":       tt.fields.url,
				"rcodes":    tt.fields.rcodes,
				"useragent": tt.fields.useragent,
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
	// Test with blank `useragent`
	proberYAML := `
url: https://www.google.com
rcodes: [ 200 ]
useragent: ""
`
	c := ACMEConf{}
	configurer, err := c.UnmarshalSettings([]byte(proberYAML))
	test.AssertNotError(t, err, "Got error for valid prober config")
	prober, err := configurer.MakeProber()
	test.AssertNotError(t, err, "Got error for valid prober config")
	test.AssertEquals(t, prober.Name(), "https://www.google.com-[200]-letsencrypt/boulder-observer-http-client")

	// Test with custom `useragent`
	proberYAML = `
url: https://www.google.com
rcodes: [ 200 ]
useragent: fancy-custom-http-client
`
	c = ACMEConf{}
	configurer, err = c.UnmarshalSettings([]byte(proberYAML))
	test.AssertNotError(t, err, "Got error for valid prober config")
	prober, err = configurer.MakeProber()
	test.AssertNotError(t, err, "Got error for valid prober config")
	test.AssertEquals(t, prober.Name(), "https://www.google.com-[200]-fancy-custom-http-client")

}
