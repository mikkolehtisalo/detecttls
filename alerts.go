package main

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// Alerts will contain alerts
type Alerts struct {
	Messages []string
}

func getAlertsFromParseResults(in ParseResults) Alerts {
	alerts := Alerts{}

	// Warn about protocol related issues
	if config.Protocol.Enabled {

		// Warn about protocol versions
		if in.HasServerHelloMessage && !config.Protocol.AllowedProts.contains(in.GuessTLSVersion()) {
			alert := fmt.Sprintf("Protocol version: %s", getTLSVersionString(in.GuessTLSVersion()))
			alerts.Messages = append(alerts.Messages, alert)
		}

		// Warn about protocol ciphers
		if in.HasServerHelloMessage &&
			(!config.Protocol.AllowedCiphersParsed.contains(in.ServerHelloCiphersuite)) {
			alert := fmt.Sprintf("Cipher: %s", config.Protocol.AllCiphers.getName(in.ServerHelloCiphersuite))
			alerts.Messages = append(alerts.Messages, alert)
		}

	}

	// Warn about server certificate related issues
	if config.Certificate.Enabled {

		// Certificate.Verify() does a lot of checking...
		opts := x509.VerifyOptions{}
		for i := range in.ServerCertificates {

			if _, err := in.ServerCertificates[i].Verify(opts); err != nil {
				alert := fmt.Sprintf("%s, cert: %s", err.Error(), in.ServerCertificates[i].Subject)
				alerts.Messages = append(alerts.Messages, alert)
			}
		}

		// Check for valid signature algorithms
		for i := range in.ServerCertificates {
			ok := false
			for _, allowedalgo := range strings.Split(config.Certificate.AllowedSignatureAlgorithms, ":") {
				if allowedalgo == in.ServerCertificates[i].SignatureAlgorithm.String() {
					ok = true
				}
			}
			if !ok {
				alert := fmt.Sprintf("Invalid certificate signature: %s", in.ServerCertificates[i].SignatureAlgorithm.String())
				alerts.Messages = append(alerts.Messages, alert)
			}
		}

		// Check for valid public key algorithms
		for i := range in.ServerCertificates {
			ok := false
			for _, allowedalgo := range strings.Split(config.Certificate.AllowedPublicKeyAlgorithms, ":") {
				if allowedalgo == in.ServerCertificates[i].PublicKeyAlgorithm.String() {
					ok = true
				}
			}
			if !ok {
				alert := fmt.Sprintf("Invalid certificate public key algorithm: %s", in.ServerCertificates[i].PublicKeyAlgorithm.String())
				alerts.Messages = append(alerts.Messages, alert)
			}
		}

	}

	return alerts
}
