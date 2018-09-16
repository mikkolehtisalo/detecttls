package main

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

// ParseResults holds results from parsing single packet
type ParseResults struct {
	SrcIP                       net.IP
	DstIP                       net.IP
	SrcPort                     layers.TCPPort
	DstPort                     layers.TCPPort
	HasTLSRecords               bool
	MinTLSRecordVersion         uint16
	HasServerHelloMessage       bool
	ServerHelloMessage          *serverHelloMsg
	MinTLSMessageVersion        uint16
	ServerHelloVersionExtension uint16
	ServerHelloCiphersuite      uint16
	TimeStamp                   time.Time
	ServerCertificates          []*x509.Certificate
}

// GuessTLSVersion attempts to figure out what TLS version was used
func (p ParseResults) GuessTLSVersion() uint16 {
	result := uint16(0)

	// If we found any TLS records, use their version
	if p.MinTLSRecordVersion > result {
		result = p.MinTLSRecordVersion
	}

	// If we found any TLS messages, use their version
	if p.MinTLSMessageVersion > result {
		result = p.MinTLSMessageVersion
	}

	// If we found any extensions they were probably overruled previous
	if p.ServerHelloVersionExtension > result {
		result = p.ServerHelloVersionExtension
	}

	return result
}

// ParsePacket parses one packet
func ParsePacket(w *Worker, j *Job) ParseResults {
	ev := ParseResults{}

	err := w.parser.DecodeLayers(j.Packet.Data(), w.decoded)
	if err != nil {
		fmt.Printf("Error decoding layers: %s\n", err)
	}

	for _, layerType := range *w.decoded {
		switch layerType {
		case layers.LayerTypeIPv6:
			ev.SrcIP = w.ip6.SrcIP
			ev.DstIP = w.ip6.DstIP
		case layers.LayerTypeIPv4:
			ev.SrcIP = w.ip4.SrcIP
			ev.DstIP = w.ip4.DstIP
		case layers.LayerTypeTCP:
			ev.TimeStamp = time.Now().UTC()
			ev.SrcPort = w.tcp.SrcPort
			ev.DstPort = w.tcp.DstPort
			records := ExtractRecordMessages(&w.tcp.Payload)
			for reci := range *records {
				// Parse all records
				switch (*records)[reci].rectype {
				case recordTypeHandshake:
					// Update versions
					ev.HasTLSRecords = true
					if (ev.MinTLSRecordVersion > (*records)[reci].vers) || (ev.MinTLSRecordVersion == 0) {
						ev.MinTLSRecordVersion = (*records)[reci].vers
					}

					// Parse ServerHello
					serverHello := serverHelloMsg{}
					serverHello.ParseMessage(&(*records)[reci].raw, &ev)

					// Parse Certificate(s)
					if config.Certificate.Enabled {
						certdata := certificateMsg{}
						certdata.ParseMessage(&(*records)[reci].raw, &ev)
					}
				}
			}
		}
	}

	return ev
}

// ExtractRecordMessages parses application layer data, returning all probable TLS message records
func ExtractRecordMessages(data *[]byte) *[]RecordMsg {
	length := len(*data)
	left := length
	result := []RecordMsg{}
	msg := RecordMsg{}

	for ok := true; ok; ok = (left > 0) {
		res := msg.unmarshal((*data)[length-left:])
		if res {
			result = append(result, msg)
			left -= int(msg.len) + recordHeaderLen
		} else {
			// If one record fails to parse, we probably want to just stop
			left = 0
		}
	}

	return &result
}

func (r *RecordMsg) unmarshal(data []byte) bool {
	if (len(data) < recordHeaderLen) || (len(data) > maxHandshake) {
		// Too short or too long
		return false
	}

	r.rectype = recordType(data[0])
	if !((r.rectype == recordTypeChangeCipherSpec) || (r.rectype == recordTypeAlert) || (r.rectype == recordTypeHandshake) || (r.rectype == recordTypeApplicationData)) {
		// Unknown record type
		return false
	}

	r.vers = uint16(data[1])<<8 | uint16(data[2])

	r.len = uint16(data[3])<<8 | uint16(data[4])
	if r.len+recordHeaderLen >= uint16(len(data)) {
		// Not enough data
		return false
	}

	r.raw = data[recordHeaderLen : r.len+recordHeaderLen]

	return true
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	// Proper Hello message starts always with this ID
	if data[0] != 0x02 {
		return false
	}

	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return false
	}
	m.sessionID = data[39 : 39+sessionIDLen]
	data = data[39+sessionIDLen:]
	if len(data) < 3 {
		return false
	}
	m.cipherSuite = uint16(data[0])<<8 | uint16(data[1])
	m.compressionMethod = data[2]
	data = data[3:]

	m.nextProtoNeg = false
	m.nextProtos = nil
	m.ocspStapling = false
	m.scts = nil
	m.ticketSupported = false
	m.alpnProtocol = ""

	if len(data) == 0 {
		// ServerHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionNextProtoNeg:
			m.nextProtoNeg = true
			d := data[:length]
			for len(d) > 0 {
				l := int(d[0])
				d = d[1:]
				if l == 0 || l > len(d) {
					return false
				}
				m.nextProtos = append(m.nextProtos, string(d[:l]))
				d = d[l:]
			}
		case extensionStatusRequest:
			if length > 0 {
				return false
			}
			m.ocspStapling = true
		case extensionSessionTicket:
			if length > 0 {
				return false
			}
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if length == 0 {
				return false
			}
			d := data[:length]
			l := int(d[0])
			d = d[1:]
			if l != len(d) {
				return false
			}

			m.secureRenegotiation = d
			m.secureRenegotiationSupported = true
		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return false
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return false
			}
			d = d[1:]
			if len(d) == 0 {
				// ALPN protocols must not be empty.
				return false
			}
			m.alpnProtocol = string(d)
		case extensionSCT:
			d := data[:length]

			if len(d) < 2 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != l || l == 0 {
				return false
			}

			m.scts = make([][]byte, 0, 3)
			for len(d) != 0 {
				if len(d) < 2 {
					return false
				}
				sctLen := int(d[0])<<8 | int(d[1])
				d = d[2:]
				if sctLen == 0 || len(d) < sctLen {
					return false
				}
				m.scts = append(m.scts, d[:sctLen])
				d = d[sctLen:]
			}
		case extensionSupportedVersions:
			// Catches only one so far
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			m.versionSupported = uint16(d[0])<<8 | uint16(d[1])
		}
		data = data[length:]
	}

	return true
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < 7 {
		return false
	}

	// Certificate message always starts with this ID
	if data[0] != 0x0b {
		return false
	}

	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return false
	}

	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return false
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return false
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}
