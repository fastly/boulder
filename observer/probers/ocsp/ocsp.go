package probers

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"software.sslmate.com/src/ocsputil"
)

// func Evaluate(
// 	ctx context.Context, certData []byte, issuerSubject []byte, issuerPubkey []byte, httpClient *http.Client) (eval Evaluation) {
// }

type certBundle struct {
	eeCert *x509.Certificate
	caCert *x509.Certificate
}

// OCSPProbe is the exported 'Prober' object for monitors configured to
// perform OCSP requests.
type OCSPProbe struct {
	cb certBundle
}

// Name returns a string that uniquely identifies the monitor.
func (p OCSPProbe) Name() string {
	return fmt.Sprintf("%s-%s-%s", p.caCert.Subject, p.caCert.SerialNumber, p.eeCert.SerialNumber)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p OCSPProbe) Kind() string {
	return "OCSP"
}

// Probe performs the configured OCSP request.
func (p OCSPProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	start := time.Now()

	// setup context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	certData := p.cb.eeCert.Raw
	issuerSubject := p.cb.caCert.RawSubject
	issuerPubkey := p.cb.caCert.RawIssuer
	httpClient := http.DefaultClient

	// do evaluation
	ocspEval := ocsputil.Evaluate(ctx, certData, issuerSubject, issuerPubkey, httpClient)

	return true, time.Since(start)
}
