package main

// #include <stdio.h>
// #include <errno.h>
// #cgo LDFLAGS: -L/opt/openssl/lib -lssl -lcrypto -Wl,-rpath,/opt/openssl/lib
// #cgo CFLAGS: -I/opt/openssl/include
// #include <openssl/err.h>
// #include <openssl/ssl.h>
// #include <openssl/safestack.h>
import "C"
import (
	"errors"
	"fmt"
)

// Ciphers is a helper for Cipher list
type Ciphers struct {
	Clist []Cipher
}

func (c *Ciphers) contains(id uint16) bool {
	result := false
	for k := range c.Clist {
		if c.Clist[k].ID == id {
			result = true
		}
	}
	return result
}

func (c *Ciphers) get(id uint16) (Cipher, error) {
	for k := range c.Clist {
		if c.Clist[k].ID == id {
			return c.Clist[k], nil
		}
	}
	return Cipher{}, errors.New("Not found")
}

func (c *Ciphers) getName(id uint16) string {
	for k := range c.Clist {
		if c.Clist[k].ID == id {
			return c.Clist[k].Name
		}
	}
	return fmt.Sprintf("unknown (0x%04x)", id)
}

// Cipher contains basic description
type Cipher struct {
	ID   uint16
	Name string
}

// GetCipherList uses libssl to query for known ciphers
func GetCipherList(ciphers string, ciphersuites string) Ciphers {
	list := Ciphers{}

	meth := C.TLS_server_method()
	ctx := C.SSL_CTX_new(meth)
	if ctx == nil {
		panic("Unable to initialize openssl context")
	}

	res := C.SSL_CTX_ctrl(ctx, C.SSL_CTRL_SET_MIN_PROTO_VERSION, 0, C.NULL)
	if res == 0 {
		panic("Unable to set minimum protocol version")
	}
	res = C.SSL_CTX_ctrl(ctx, C.SSL_CTRL_SET_MAX_PROTO_VERSION, 0, C.NULL)
	if res == 0 {
		panic("Unable to set maximum protocol version")
	}

	// TLS < 1.3
	res2 := C.SSL_CTX_set_cipher_list(ctx, C.CString(ciphers))
	if res2 == 0 {
		panic("Unable to set ciphers")
	}

	// TLS 1.3
	res3 := C.SSL_CTX_set_ciphersuites(ctx, C.CString(ciphersuites))
	if res3 == 0 {
		panic("Unable to set ciphersuites")
	}

	ssl := C.SSL_new(ctx)
	if ssl == nil {
		panic("Unable to initialize new ssl structure")
	}
	defer C.SSL_free(ssl)

	sk := C.SSL_get_ciphers(ssl)
	defer C.sk_SSL_CIPHER_free(sk)

	list = getcipherinfo(sk)

	return list
}

func getcipherinfo(sk *_Ctype_struct_stack_st_SSL_CIPHER) Ciphers {
	list := Ciphers{}
	skcount := int(C.sk_SSL_CIPHER_num(sk))

	for i := 0; i < skcount; i++ {
		cipher := Cipher{}
		ciph := C.sk_SSL_CIPHER_value(sk, C.int(i))
		id := C.SSL_CIPHER_get_id(ciph)
		id0 := (int)(id >> 24)
		id1 := (int)((id >> 16) & 0xff)
		id2 := (int)((id >> 8) & 0xff)
		id3 := (int)(id & 0xff)

		if (id & 0xff000000) == 0x03000000 {
			// TLS
			cipher.ID = uint16(id3 + (id2 << 8))
		} else {
			// SSLv3
			cipher.ID = uint16(id3 + (id2 << 8) + (id1 << 16) + (id0 << 24))
		}

		nm := C.SSL_CIPHER_get_name(ciph)
		if nm == nil {
			cipher.Name = "UNKNOWN"
		} else {
			cipher.Name = C.GoString(nm)
		}

		list.Clist = append(list.Clist, cipher)
	}
	return list
}
