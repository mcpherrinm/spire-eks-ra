package grpcspiffe

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"

	"github.com/pkg/errors"
	"github.com/spiffe/spire/api/workload"
	workloadprotos "github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func getCertificate(resp *workloadprotos.X509SVIDResponse) (*tls.Certificate, error) {
	svids := resp.GetSvids()
	if len(svids) != 1 {
		log.Fatalf("Only support 1 svid, got %d", len(svids))
	}

	// TODO: We don't really need to parse all the certs, but it's easy
	certs, err := x509.ParseCertificates(svids[0].X509Svid)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse certificate from workload api")
	}
	key, err := x509.ParsePKCS8PrivateKey(svids[0].X509SvidKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse key from workload api")
	}

	var certsRaw [][]byte
	for _, cert := range certs {
		certsRaw = append(certsRaw, cert.Raw)
	}

	tlsCertificate := tls.Certificate{
		Certificate: certsRaw,
		PrivateKey:  key,
		Leaf:        certs[0],
	}

	return &tlsCertificate, nil
}

func validateCerts(spiffeID string, rawCerts [][]byte, resp *workloadprotos.X509SVIDResponse) error {
	var certs []*x509.Certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return errors.Wrap(err, "parsing peer certificate")
		}
		certs = append(certs, cert)
	}

	intermediates := x509.NewCertPool()
	for _, intermediate := range certs[1:] {
		intermediates.AddCert(intermediate)
	}

	spiffe, err := url.Parse(spiffeID)
	if err != nil {
		return errors.Wrap(err, "parsing spiffe ID")
	}

	mySpiffeID, err := url.Parse(resp.Svids[0].SpiffeId)
	if err != nil {
		return errors.Wrap(err, "parsing my own spiffe ID")
	}

	log.Printf("My spiffe ID: %s", mySpiffeID.String())

	roots := x509.NewCertPool()
	if mySpiffeID.Host == spiffe.Host {
		// Same trust domain
		bundle, err := x509.ParseCertificates(resp.Svids[0].GetBundle())
		if err != nil {
			return errors.Wrap(err, "parsing bundle")
		}
		for _, cert := range bundle {
			roots.AddCert(cert)
		}
	} else {
		var ok bool
		rootDER, ok := resp.GetFederatedBundles()[spiffe.Host]
		if !ok {
			return fmt.Errorf("no federated bundle for %s: %q", spiffe.Host, resp.FederatedBundles)
		}
		root, err := x509.ParseCertificate(rootDER)
		if err != nil {
			return errors.Wrap(err, "parsing root")
		}
		roots.AddCert(root)
	}

	verifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}

	chains, err := certs[0].Verify(verifyOpts)
	if err != nil {
		return err
	}

	verifiedLeaf := chains[0][0]

	uris := verifiedLeaf.URIs
	if len(uris) != 1 {
		return fmt.Errorf("SVIDs have exactly 1 URI SAN: %q", uris)
	}
	if uris[0].Scheme != "spiffe" {
		return fmt.Errorf("SVIDs have URI SAN of scheme spiffe, not %s", uris[0].Scheme)
	}

	if uri := uris[0].String(); uri != spiffeID {
		return fmt.Errorf("server has wrong SPIFFE ID: %s, not %s", uri, spiffeID)
	}

	return nil
}

// WithSpiffe is a GRPC DialOption that configures SPIFFE TLS TransportCredentials for GRPC
// It takes a SPIFFE ID that this grpc client should be connecting to
func WithSpiffe(spiffeID string, client workload.X509Client) grpc.DialOption {
	// Block until a SPIFFE ID is available
	log.Printf("Blocking until a SPIFFE ID is available")
	resp := <-client.UpdateChan()
	log.Printf("WithSpiffe ID %s", resp.Svids[0].SpiffeId)

	tlsConfig := &tls.Config{
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			resp, err := client.CurrentSVID()
			if err != nil {
				return nil, errors.Wrap(err, "getting client certificate")
			}
			return getCertificate(resp)
		},
		// We set InsecureSkipVerify true and pass our own validator function so we can reload roots from the workload
		// API and implement roots per trust domain
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, alwaysNil [][]*x509.Certificate) error {
			resp, err := client.CurrentSVID()
			if err != nil {
				return errors.Wrap(err, "getting federated trust")
			}
			return validateCerts(spiffeID, rawCerts, resp)
		},
	}

	return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
}
