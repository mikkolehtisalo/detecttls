# DetectTLS

DetectTLS is a passive SSL/TLS traffic analyzer designed to alert about the use of insecure protocol versions, ciphers, and certificates.

## Features

* Analyzes traffic from pcap file, or network
* Passive, does not affect the monitored services
* Detects protocol versions, and ciphers
* Detects certificate signature algorithms, public key algorithms, expired or future validity dates, and signing CAs
* Generates alerts based on configuration, eg. for certificates signed by unknown authority
* Generates alerts to local console, or [Graylog](https://www.graylog.org/) - see this [screenshot](https://raw.githubusercontent.com/mikkolehtisalo/detecttls/master/screenshot.png) for example.
* Scales well

## Installation and usage

Most systems still have openssl <1.1.1, so you probably have to build and install a local version from source:

```
wget https://www.openssl.org/source/openssl-1.1.1.tar.gz
tar xvzf openssl-1.1.1.tar.gz
cd openssl-1.1.1
./config --prefix=/opt/openssl --openssldir=/usr/local/ssl
make
make install
```

After that use the typical Go tools, for example:

```
go get github.com/mikkolehtisalo/detecttls
go build github.com/mikkolehtisalo/detecttls
./detecttls -cfg ~/go/src/github.com/mikkolehtisalo/detecttls/config.json
```

## Implementation notes

The implementation is stateless, and does not take the state machine of SSL/TLS protocols into account. This enables scaling up near linearly - just add more hardware and multiplex the packets! 

Passive implementation means you have to be able to sniff the network traffic. For example add a monitoring port to a router. On the other hand, this ensures detecttls can't negatively impact applications, which is nice especially for legacy systems.

Basic optimization has been done. It should be somewhat easy to reach gigabyte/s level analysis performance on proper server hardware.

The contents of ChangeCipherSpecs are encrypted. It is not possible to detect re-negotiating using bad settings (algorithms etc.). 

Since TLS 1.3 the Certificate message is encrypted, making it impossible to passively check the server certificate for issues.

Openssl separated TLS 1.3 cipher suites from previously used cipher APIs to reduce the risk of misconfigurations. This implementation follows similar logic.

It would also be possible to check for key exchange (DH) key lengths. Might be worth adding later.

If you get too many "certificate signed by unknown authority" messages, add the missing certificates to you system's default store (eg. */etc/ssl/certs*). You should end up with getting alerts only about self-signed certificates and such.

## Configuration

See `config.json`.

### Protocol related options

*enabled*: enable alerts [true, false]

*allowed_versions*: colon separated list of allowed protocol versions [VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13]

*allowed_ciphers*: colon separated list of allowed ciphers for upto TLS 1.2 [see *openssl ciphers*]

*allowed_ciphersuites*: colon separated list of allowed cipher suites for TLS 1.3 [see *openssl ciphers*]

### Certificate related options

*enabled*: Enable alerts [true, false]

*allowed_signature_algorithms*: allowed certificate signature algorithms [see *https://golang.org/pkg/crypto/x509/#SignatureAlgorithm*]

*allowed_public_key_algorithms*: allowed public key algorithms [ECDSA, DSA, RSA]

### Input related options

*source*: source of pcap data [file, network]

*filename*: filename for data

*interface*: network interface

*promiscuous*: enter promiscuous mode [true, false]

*snaplen*: snarf snaplen bytes of data from each packet

### Performance related options

*max_workers*: workers in packet parsing queue

*max_queue*: packet parsing queue size

### Logging related options

*console*: log alerts to console [true, false]

*graylog*: log alerts to graylog using http(s) GELF input [true, false]

*graylog_url*: URL for the input

*graylog_allow_insecure*: check the certificate of Graylog, if using HTTPS

*graylog_ca_certificates*: CA certificates for the Graylog's certificate

## Debugging related options

*profile_cpu*: enable cpu profiling [true, false]

*profile_mem*: enable memory profiling [true, false]

