package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// TLS protocol versions
const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// Handshake related assumptions
const (
	recordHeaderLen = 5     // record header length
	maxHandshake    = 65536 // maximum handshake we support (protocol max is 16 MB)
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest       uint8 = 0
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeNewSessionTicket   uint8 = 4
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
	typeCertificateStatus  uint8 = 22
	typeNextProtocol       uint8 = 67 // Not IANA assigned
)

// RecordMsg represents TLS protocol record
type RecordMsg struct {
	rectype recordType
	vers    uint16
	len     uint16
	raw     []byte
}

func getTLSVersionString(in uint16) string {
	var res string
	switch in {
	case 0x0300:
		res = "VersionSSL30"
	case 0x0301:
		res = "VersionTLS10"
	case 0x0302:
		res = "VersionTLS11"
	case 0x0303:
		res = "VersionTLS12"
	case 0x0304:
		res = "VersionTLS13"
	default:
		res = fmt.Sprintf("unknown (0x%04x)", in)
	}
	return res
}

func getTLSVersionFromString(in string) uint16 {
	switch in {
	case "VersionSSL30":
		return 0x0300
	case "VersionTLS10":
		return 0x0301
	case "VersionTLS11":
		return 0x0302
	case "VersionTLS12":
		return 0x0303
	case "VersionTLS13":
		return 0x0304
	default:
		return 0
	}
}

func (m serverHelloMsg) getCipherSuite(c Ciphers) string {
	cipher, err := c.get(m.cipherSuite)
	if err != nil {
		return fmt.Sprintf("unknown (0x%04x)", m.cipherSuite)
	}
	return cipher.Name
}

// TLS extension numbers
const (
	extensionServerName          uint16 = 0
	extensionStatusRequest       uint16 = 5
	extensionSupportedCurves     uint16 = 10
	extensionSupportedPoints     uint16 = 11
	extensionSignatureAlgorithms uint16 = 13
	extensionALPN                uint16 = 16
	extensionSCT                 uint16 = 18 // https://tools.ietf.org/html/rfc6962#section-6
	extensionSessionTicket       uint16 = 35
	extensionSupportedVersions   uint16 = 43
	extensionNextProtoNeg        uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo   uint16 = 0xff01
)

type serverHelloMsg struct {
	raw                          []byte
	vers                         uint16
	random                       []byte
	sessionID                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	nextProtoNeg                 bool
	nextProtos                   []string
	ocspStapling                 bool
	scts                         [][]byte
	ticketSupported              bool
	secureRenegotiation          []byte
	secureRenegotiationSupported bool
	alpnProtocol                 string
	versionSupported             uint16
}

// ParseMessage parses one ServerHello message and adds results to ParseResults
func (m *serverHelloMsg) ParseMessage(raw *[]byte, ev *ParseResults) {
	ok := m.unmarshal(*raw)
	if ok {
		ev.ServerHelloMessage = m
		ev.HasServerHelloMessage = true
		if (ev.MinTLSMessageVersion > ev.ServerHelloMessage.vers) || (ev.MinTLSMessageVersion == 0) {
			ev.MinTLSMessageVersion = ev.ServerHelloMessage.vers
		}
		if ev.ServerHelloMessage.versionSupported != 0 {
			ev.ServerHelloVersionExtension = ev.ServerHelloMessage.versionSupported
		}
		ev.ServerHelloCiphersuite = ev.ServerHelloMessage.cipherSuite
	}
}

type prots []uint16

func (p *prots) contains(id uint16) bool {
	for _, prot := range *p {
		if prot == id {
			return true
		}
	}
	return false
}

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

// ParseMessage parses one Certificate message and adds the results to parseresults
func (m *certificateMsg) ParseMessage(raw *[]byte, ev *ParseResults) {
	ok2 := m.unmarshal(*raw)
	if ok2 && len(m.certificates) > 0 {
		for i := range m.certificates {
			cert, err := x509.ParseCertificate(m.certificates[i])
			if err != nil {
				fmt.Printf("Unable to parse certificate: %s\n", err)
			}
			ev.ServerCertificates = append(ev.ServerCertificates, cert)
		}
	}
}

// Config struct
type Config struct {
	Protocol    ProtocolConfig    `json:"protocol"`
	Certificate CertificateConfig `json:"certificate"`
	Input       InputConfig       `json:"input"`
	Performance PerformanceConfig `json:"performance"`
	Logging     LoggingConfig     `json:"logging"`
	Debug       DebugConfig       `json:"debug"`
}

// ProtocolConfig holds protocol related configuration
type ProtocolConfig struct {
	Enabled              bool   `json:"enabled"`
	AllowedVersions      string `json:"allowed_versions"`
	AllowedCiphers       string `json:"allowed_ciphers"`
	AllowedCiphersuites  string `json:"allowed_ciphersuites"`
	AllowedProts         prots
	AllCiphers           Ciphers `json:"-"`
	AllowedCiphersParsed Ciphers `json:"-"`
}

// CertificateConfig holds certificate related configuration
type CertificateConfig struct {
	Enabled                    bool   `json:"enabled"`
	AllowedSignatureAlgorithms string `json:"allowed_signature_algorithms"`
	AllowedPublicKeyAlgorithms string `json:"allowed_public_key_algorithms"`
	AllowExpiredOrFuture       bool   `json:"allow_expired_or_future"`
	AllowSelfSigned            bool   `json:"allow_self_signed"`
}

// InputConfig holds input related configuration
type InputConfig struct {
	Source      string `json:"source"`
	Filename    string `json:"filename"`
	Interface   string `json:"interface"`
	Promiscuous bool   `json:"promiscuous"`
	Snaplen     int    `json:"snaplen"`
}

// PerformanceConfig holds performance related configuration
type PerformanceConfig struct {
	MaxWorkers int `json:"max_workers"`
	MaxQueue   int `json:"max_queue"`
}

// DebugConfig holds debugging related settings
type DebugConfig struct {
	ProfileCPU bool `json:"profile_cpu"`
	ProfileMEM bool `json:"profile_mem"`
}

// LoggingConfig holds logging related settings
type LoggingConfig struct {
	Console               bool   `json:"console"`
	Graylog               bool   `json:"graylog"`
	GraylogURL            string `json:"graylog_url"`
	useTLS                bool
	GraylogAllowInsecure  bool   `json:"graylog_allow_insecure"`
	GraylogCACertificates string `json:"graylog_ca_certificates"`
	pemData               []byte
}

// Initialize reads configuration from file and initializes configuration
func (c *Config) Initialize(filename string) {
	jsonFile, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer jsonFile.Close()

	jsonData, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(jsonData, c)
	if err != nil {
		panic(err)
	}

	// Setup Graylog logging
	if c.Logging.Graylog {
		if strings.Index(c.Logging.GraylogURL, "https") == 0 {
			c.Logging.useTLS = true
		}
		if c.Logging.useTLS {
			var err error
			c.Logging.pemData, err = ioutil.ReadFile(c.Logging.GraylogCACertificates)
			if err != nil {
				panic(err)
			}
		}
	}

	// Setup protocols with help of openssl
	// SSL_CTX_set_ciphersuites does not seem to support ALL
	c.Protocol.AllCiphers = GetCipherList("ALL", "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256")
	if len(c.Protocol.AllCiphers.Clist) == 0 {
		panic("Unable to retrieve any ciphers from libssl")
	}
	c.Protocol.AllowedCiphersParsed = GetCipherList(c.Protocol.AllowedCiphers, c.Protocol.AllowedCiphersuites)
	if len(c.Protocol.AllowedCiphersParsed.Clist) == 0 {
		panic("Unable to parse any allowed ciphers")
	}

	protocols := strings.Split(c.Protocol.AllowedVersions, ":")
	for _, protocol := range protocols {
		vers := getTLSVersionFromString(protocol)
		if vers != 0 {
			c.Protocol.AllowedProts = append(c.Protocol.AllowedProts, vers)
		}
	}
}
