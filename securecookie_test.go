// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	fuzz "github.com/google/gofuzz"
)

// Asserts that cookieError, cookieLengthError, and MultiError are Error implementations.
var _ Error = cookieError{}
var _ Error = cookieLengthError{}
var _ Error = MultiError{}

var testCookies = []interface{}{
	map[string]string{"foo": "bar"},
	map[string]string{"baz": "ding"},
}

var testStrings = []string{"foo", "bar", "baz"}

func TestSecureCookie(t *testing.T) {
	s1 := New([]byte("12345"), []byte("1234567890123456"))
	s2 := New([]byte("54321"), []byte("6543210987654321"))
	value := map[string]interface{}{
		"foo": "bar",
		"baz": 128,
	}

	for i := 0; i < 50; i++ {
		// Running this multiple times to check if any special character
		// breaks encoding/decoding.
		encoded, err1 := s1.Encode("sid", value)
		if err1 != nil {
			t.Error(err1)
			continue
		}
		dst := make(map[string]interface{})
		err2 := s1.Decode("sid", encoded, &dst)
		if err2 != nil {
			t.Fatalf("%v: %v", err2, encoded)
		}
		if !reflect.DeepEqual(dst, value) {
			t.Fatalf("Expected %v, got %v.", value, dst)
		}
		dst2 := make(map[string]interface{})
		err3 := s2.Decode("sid", encoded, &dst2)
		if err3 == nil {
			t.Fatalf("Expected failure decoding.")
		}
		err4, ok := err3.(Error)
		if !ok {
			t.Fatalf("Expected error to implement Error, got: %#v", err3)
		}
		if !err4.IsDecode() {
			t.Fatalf("Expected DecodeError, got: %#v", err4)
		}

		// Test other error type flags.
		if err4.IsUsage() {
			t.Fatalf("Expected IsUsage() == false, got: %#v", err4)
		}
		if err4.IsInternal() {
			t.Fatalf("Expected IsInternal() == false, got: %#v", err4)
		}
	}
}

func TestSecureCookieNilKey(t *testing.T) {
	s1 := New(nil, nil)
	value := map[string]interface{}{
		"foo": "bar",
		"baz": 128,
	}
	_, err := s1.Encode("sid", value)
	if err != errHashKeyNotSet {
		t.Fatal("Wrong error returned:", err)
	}
}

func TestDecodeInvalid(t *testing.T) {
	// List of invalid cookies, which must not be accepted, base64-decoded
	// (they will be encoded before passing to Decode).
	invalidCookies := []string{
		"",
		" ",
		"\n",
		"||",
		"|||",
		"cookie",
	}
	s := New([]byte("12345"), nil)
	var dst string
	for i, v := range invalidCookies {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding,
			base64.URLEncoding,
		} {
			err := s.Decode("name", enc.EncodeToString([]byte(v)), &dst)
			if err == nil {
				t.Fatalf("%d: expected failure decoding", i)
			}
			err2, ok := err.(Error)
			if !ok || !err2.IsDecode() {
				t.Fatalf("%d: Expected IsDecode(), got: %#v", i, err)
			}
		}
	}
}

func TestAuthentication(t *testing.T) {
	hash := hmac.New(sha256.New, []byte("secret-key"))
	for _, value := range testStrings {
		hash.Reset()
		signed := createMac(hash, []byte(value))
		hash.Reset()
		err := verifyMac(hash, []byte(value), signed)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestEncryption(t *testing.T) {
	block, err := aes.NewCipher([]byte("1234567890123456"))
	if err != nil {
		t.Fatalf("Block could not be created")
	}
	var encrypted, decrypted []byte
	for _, value := range testStrings {
		if encrypted, err = encrypt(block, []byte(value)); err != nil {
			t.Error(err)
		} else {
			if decrypted, err = decrypt(block, encrypted); err != nil {
				t.Error(err)
			}
			if string(decrypted) != value {
				t.Errorf("Expected %v, got %v.", value, string(decrypted))
			}
		}
	}
}

func TestGobSerialization(t *testing.T) {
	var (
		sz           GobEncoder
		serialized   []byte
		deserialized map[string]string
		err          error
	)
	for _, value := range testCookies {
		if serialized, err = sz.Serialize(value); err != nil {
			t.Error(err)
		} else {
			deserialized = make(map[string]string)
			if err = sz.Deserialize(serialized, &deserialized); err != nil {
				t.Error(err)
			}
			if fmt.Sprintf("%v", deserialized) != fmt.Sprintf("%v", value) {
				t.Errorf("Expected %v, got %v.", value, deserialized)
			}
		}
	}
}

func TestJSONSerialization(t *testing.T) {
	var (
		sz           JSONEncoder
		serialized   []byte
		deserialized map[string]string
		err          error
	)
	for _, value := range testCookies {
		if serialized, err = sz.Serialize(value); err != nil {
			t.Error(err)
		} else {
			deserialized = make(map[string]string)
			if err = sz.Deserialize(serialized, &deserialized); err != nil {
				t.Error(err)
			}
			if fmt.Sprintf("%v", deserialized) != fmt.Sprintf("%v", value) {
				t.Errorf("Expected %v, got %v.", value, deserialized)
			}
		}
	}
}

func TestNopSerialization(t *testing.T) {
	cookieData := "fooobar123"
	sz := NopEncoder{}

	if _, err := sz.Serialize(cookieData); err != errValueNotByte {
		t.Fatal("Expected error passing string")
	}
	dat, err := sz.Serialize([]byte(cookieData))
	if err != nil {
		t.Fatal(err)
	}
	if (string(dat)) != cookieData {
		t.Fatal("Expected serialized data to be same as source")
	}

	var dst []byte
	if err = sz.Deserialize(dat, dst); err != errValueNotBytePtr {
		t.Fatal("Expect error unless you pass a *[]byte")
	}
	if err = sz.Deserialize(dat, &dst); err != nil {
		t.Fatal(err)
	}
	if (string(dst)) != cookieData {
		t.Fatal("Expected deserialized data to be same as source")
	}
}

func TestEncoding(t *testing.T) {
	for _, value := range testStrings {
		encoded := encode([]byte(value))
		decoded, err := decode(encoded)
		if err != nil {
			t.Error(err)
		} else if string(decoded) != value {
			t.Errorf("Expected %v, got %s.", value, string(decoded))
		}
	}
}

func TestMultiError(t *testing.T) {
	s1, s2 := New(nil, nil), New(nil, nil)
	_, err := EncodeMulti("sid", "value", s1, s2)
	if len(err.(MultiError)) != 2 {
		t.Errorf("Expected 2 errors, got %s.", err)
	} else {
		if !strings.Contains(err.Error(), "hash key is not set") {
			t.Errorf("Expected missing hash key error, got %s.", err.Error())
		}
		ourErr, ok := err.(Error)
		if !ok || !ourErr.IsUsage() {
			t.Fatalf("Expected error to be a usage error; got %#v", err)
		}
		if ourErr.IsDecode() {
			t.Errorf("Expected error NOT to be a decode error; got %#v", ourErr)
		}
		if ourErr.IsInternal() {
			t.Errorf("Expected error NOT to be an internal error; got %#v", ourErr)
		}
	}
}

func TestMultiNoCodecs(t *testing.T) {
	_, err := EncodeMulti("foo", "bar")
	if err != errNoCodecs {
		t.Errorf("EncodeMulti: bad value for error, got: %v", err)
	}

	var dst []byte
	err = DecodeMulti("foo", "bar", &dst)
	if err != errNoCodecs {
		t.Errorf("DecodeMulti: bad value for error, got: %v", err)
	}
}

func TestMissingKey(t *testing.T) {
	emptyKeys := [][]byte{
		nil,
		[]byte(""),
	}

	for _, key := range emptyKeys {
		s1 := New(key, nil)

		var dst []byte
		err := s1.Decode("sid", "value", &dst)
		if err != errHashKeyNotSet {
			t.Fatalf("Expected %#v, got %#v", errHashKeyNotSet, err)
		}
		if err2, ok := err.(Error); !ok || !err2.IsUsage() {
			t.Errorf("Expected missing hash key to be IsUsage(); was %#v", err)
		}
	}
}

// ----------------------------------------------------------------------------

type FooBar struct {
	Foo int
	Bar string
}

func TestCustomType(t *testing.T) {
	s1 := New([]byte("12345"), []byte("1234567890123456"))
	// Type is not registered in gob. (!!!)
	src := &FooBar{42, "bar"}
	encoded, _ := s1.Encode("sid", src)

	dst := &FooBar{}
	_ = s1.Decode("sid", encoded, dst)
	if dst.Foo != 42 || dst.Bar != "bar" {
		t.Fatalf("Expected %#v, got %#v", src, dst)
	}
}

type Cookie struct {
	B bool
	I int
	S string
}

func FuzzEncodeDecode(f *testing.F) {
	fuzzer := fuzz.New()
	s1 := New([]byte("12345"), []byte("1234567890123456"))
	s1.maxLength = 0

	for i := 0; i < 100000; i++ {
		var c Cookie
		fuzzer.Fuzz(&c)
		f.Add(c.B, c.I, c.S)
	}

	f.Fuzz(func(t *testing.T, b bool, i int, s string) {
		c := Cookie{b, i, s}
		encoded, err := s1.Encode("sid", c)
		if err != nil {
			t.Errorf("Encode failed: %v", err)
		}
		dc := Cookie{}
		err = s1.Decode("sid", encoded, &dc)
		if err != nil {
			t.Errorf("Decode failed: %v", err)
		}
		if dc != c {
			t.Fatalf("Expected %v, got %v.", s, dc)
		}
	})
}

func TestTimestampExpired(t *testing.T) {
	s := New([]byte("hash-key-12345678901234567890123"), nil)
	s.MaxAge(3600)

	now := time.Now().UTC().Unix()
	s.timeFunc = func() int64 { return now }

	encoded, err := s.Encode("test_cookie", "hello")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	var dst string
	if err := s.Decode("test_cookie", encoded, &dst); err != nil {
		t.Fatalf("Decode failed at valid time: %v", err)
	}

	s.timeFunc = func() int64 { return now + 3601 }
	err = s.Decode("test_cookie", encoded, &dst)
	if err == nil {
		t.Fatal("Expected error for expired cookie, got nil")
	}

	if !errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("Expected errors.Is(err, ErrTimestampExpired), got %v", err)
	}
	if !IsTimestampExpired(err) {
		t.Fatalf("Expected IsTimestampExpired(err) == true, got %v", err)
	}
	if errors.Is(err, ErrMacInvalid) {
		t.Fatalf("Expected !errors.Is(err, ErrMacInvalid), got true")
	}
	if IsMacInvalid(err) {
		t.Fatalf("Expected IsMacInvalid(err) == false, got true")
	}
	scErr, ok := err.(Error)
	if !ok || !scErr.IsDecode() {
		t.Fatalf("Expected decode error, got %v", err)
	}
}

func TestTimestampTooNew(t *testing.T) {
	s := New([]byte("hash-key-12345678901234567890123"), nil)
	s.MinAge(60)

	now := time.Now().UTC().Unix()
	s.timeFunc = func() int64 { return now }

	encoded, err := s.Encode("test_cookie", "hello")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	var dst string
	s.timeFunc = func() int64 { return now + 30 }
	err = s.Decode("test_cookie", encoded, &dst)
	if err == nil {
		t.Fatal("Expected error for too new cookie, got nil")
	}

	if !errors.Is(err, ErrTimestampTooNew) {
		t.Fatalf("Expected errors.Is(err, ErrTimestampTooNew), got %v", err)
	}
	if !IsTimestampTooNew(err) {
		t.Fatalf("Expected IsTimestampTooNew(err) == true, got %v", err)
	}
	if errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("Expected !errors.Is(err, ErrTimestampExpired), got true")
	}
	if IsTimestampExpired(err) {
		t.Fatalf("Expected IsTimestampExpired(err) == false, got true")
	}
	scErr, ok := err.(Error)
	if !ok || !scErr.IsDecode() {
		t.Fatalf("Expected decode error, got %v", err)
	}

	s.timeFunc = func() int64 { return now + 65 }
	if err := s.Decode("test_cookie", encoded, &dst); err != nil {
		t.Fatalf("Decode failed after MinAge: %v", err)
	}
}

func TestMacInvalid(t *testing.T) {
	s := New([]byte("hash-key-12345678901234567890123"), nil)
	encoded, err := s.Encode("test_cookie", "hello")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	raw, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := base64.URLEncoding.EncodeToString(raw)

	var dst string
	err = s.Decode("test_cookie", tampered, &dst)
	if err == nil {
		t.Fatal("Expected error for tampered cookie, got nil")
	}

	if !errors.Is(err, ErrMacInvalid) {
		t.Fatalf("Expected errors.Is(err, ErrMacInvalid), got %v", err)
	}
	if !IsMacInvalid(err) {
		t.Fatalf("Expected IsMacInvalid(err) == true, got %v", err)
	}
	if errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("Expected !errors.Is(err, ErrTimestampExpired), got true")
	}
	if IsTimestampExpired(err) {
		t.Fatalf("Expected IsTimestampExpired(err) == false, got true")
	}
}

func TestLengthErrors(t *testing.T) {
	s := New([]byte("hash-key-12345678901234567890123"), nil)
	s.MaxLength(20)

	_, err := s.Encode("test_cookie", "a very long cookie value exceeding max length limit")
	if err == nil {
		t.Fatal("Expected error when encoded value exceeds MaxLength")
	}
	if !errors.Is(err, ErrEncodedValueTooLong) {
		t.Fatalf("Expected errors.Is(err, ErrEncodedValueTooLong), got %v", err)
	}
	scErr, ok := err.(Error)
	if !ok || !scErr.IsUsage() {
		t.Fatalf("Expected usage error for ErrEncodedValueTooLong, got %v", err)
	}

	var dst string
	err = s.Decode("test_cookie", "this-value-is-longer-than-twenty-characters", &dst)
	if err == nil {
		t.Fatal("Expected error when value to decode exceeds MaxLength")
	}
	if !errors.Is(err, ErrValueToDecodeTooLong) {
		t.Fatalf("Expected errors.Is(err, ErrValueToDecodeTooLong), got %v", err)
	}
	if errors.Is(err, ErrEncodedValueTooLong) {
		t.Fatalf("Expected !errors.Is(err, ErrEncodedValueTooLong), got true")
	}
	scErr, ok = err.(Error)
	if !ok || !scErr.IsDecode() {
		t.Fatalf("Expected decode error for ErrValueToDecodeTooLong, got %v", err)
	}
}

func TestMultiErrorMatching(t *testing.T) {
	s1 := New([]byte("hash-key-1-123456789012345678901"), nil)
	s2 := New([]byte("hash-key-2-123456789012345678901"), nil)
	s1.MaxAge(10)

	now := time.Now().UTC().Unix()
	s1.timeFunc = func() int64 { return now }
	encoded, err := s1.Encode("test_cookie", "secret-payload")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	s1.timeFunc = func() int64 { return now + 100 }
	var dst string
	err = DecodeMulti("test_cookie", encoded, &dst, s1, s2)
	if err == nil {
		t.Fatal("Expected error from DecodeMulti")
	}

	if !errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("Expected MultiError to match ErrTimestampExpired")
	}
	if !IsTimestampExpired(err) {
		t.Fatalf("Expected IsTimestampExpired(err) == true on MultiError")
	}
	if !errors.Is(err, ErrMacInvalid) {
		t.Fatalf("Expected MultiError to match ErrMacInvalid")
	}
	if !IsMacInvalid(err) {
		t.Fatalf("Expected IsMacInvalid(err) == true on MultiError")
	}
	if errors.Is(err, ErrHashKeyNotSet) {
		t.Fatalf("Expected MultiError not to match ErrHashKeyNotSet")
	}

	var multiErr MultiError
	if !errors.As(err, &multiErr) {
		t.Fatalf("Expected errors.As to match MultiError")
	}
	if len(multiErr) != 2 {
		t.Fatalf("Expected 2 errors in MultiError, got %d", len(multiErr))
	}

	unwrapped := multiErr.Unwrap()
	if len(unwrapped) != 2 {
		t.Fatalf("Expected Unwrap to return 2 errors, got %d", len(unwrapped))
	}
}

func TestSentinelErrorsMatching(t *testing.T) {
	sNoHash := New(nil, nil)
	var dst string
	err := sNoHash.Decode("test", "dummy", &dst)
	if !errors.Is(err, ErrHashKeyNotSet) {
		t.Fatalf("Expected ErrHashKeyNotSet, got %v", err)
	}

	sNoBlock := New([]byte("hash-key"), nil)
	sNoBlock.BlockFunc(aes.NewCipher)
	_, err = sNoBlock.Encode("test", "data")
	if !errors.Is(err, ErrBlockKeyNotSet) {
		t.Fatalf("Expected ErrBlockKeyNotSet, got %v", err)
	}

	_, err = EncodeMulti("test", "data")
	if !errors.Is(err, ErrNoCodecs) {
		t.Fatalf("Expected ErrNoCodecs on EncodeMulti, got %v", err)
	}
	err = DecodeMulti("test", "data", &dst)
	if !errors.Is(err, ErrNoCodecs) {
		t.Fatalf("Expected ErrNoCodecs on DecodeMulti, got %v", err)
	}

	sValid := New([]byte("hash-key-12345678901234567890123"), nil)
	err = sValid.Decode("test", "%%%invalid-base64%%%", &dst)
	if !errors.Is(err, ErrBadBase64) {
		t.Fatalf("Expected ErrBadBase64 on invalid base64, got %v", err)
	}
}

func TestCookieErrorUnwrap(t *testing.T) {
	underlying := errors.New("underlying cause")
	wrapped := cookieError{
		typ:   decodeError,
		msg:   "failed to deserialize",
		cause: underlying,
	}

	if !errors.Is(wrapped, underlying) {
		t.Fatalf("Expected errors.Is to unwrap to underlying cause")
	}
	if errors.Unwrap(wrapped) != underlying {
		t.Fatalf("Expected errors.Unwrap to return underlying cause")
	}
}
