package widevine

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/cmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math"
	"time"

	"google.golang.org/protobuf/proto"
)

type CDM struct {
	privateKey *rsa.PrivateKey
	clientID   []byte
	sessionID  [32]byte

	widevineCencHeader      WidevineCencHeader
	signedDeviceCertificate SignedDeviceCertificate
	privacyMode             bool
}

type Key struct {
	ID    []byte
	Type  License_KeyContainer_KeyType
	Value []byte
}

// Creates a new CDM object with the specified device information.
func NewCDM(privateKey string, clientID []byte, initData []byte) (CDM, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return CDM{}, errors.New("failed to decode device private key")
	}
	keyParsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return CDM{}, err
	}

	var widevineCencHeader WidevineCencHeader
	if len(initData) < 32 {
		return CDM{}, errors.New("initData not long enough")
	}
	if err := proto.Unmarshal(initData[32:], &widevineCencHeader); err != nil {
		return CDM{}, err
	}

	sessionID := func() (s [32]byte) {
		c := []byte("ABCDEF0123456789")
		for i := 0; i < 16; i++ {
			s[i] = c[randIntn(len(c))]
		}
		s[16] = '0'
		s[17] = '1'
		for i := 18; i < 32; i++ {
			s[i] = '0'
		}
		return s
	}()

	return CDM{
		privateKey: keyParsed,
		clientID:   clientID,

		widevineCencHeader: widevineCencHeader,

		sessionID: sessionID,
	}, nil
}

// Creates a new CDM object using the default device configuration.
func NewDefaultCDM(initData []byte) (CDM, error) {
	return NewCDM(DefaultPrivateKey, DefaultClientID, initData)
}

// Sets a device certificate.  This is makes generating the license request
// more complicated but is supported.  This is usually not necessary for most
// Widevine applications.
func (c *CDM) SetServiceCertificate(certData []byte) error {
	var message SignedMessage
	if err := proto.Unmarshal(certData, &message); err != nil {
		return err
	}
	if err := proto.Unmarshal(message.Msg, &c.signedDeviceCertificate); err != nil {
		return err
	}
	c.privacyMode = true
	return nil
}

// Generates the license request data.  This is sent to the license server via
// HTTP POST and the server in turn returns the license response.
func (c *CDM) GetLicenseRequest() ([]byte, error) {
	var licenseRequest SignedLicenseRequest
	licenseRequest.Msg = new(LicenseRequest)
	licenseRequest.Msg.ContentId = new(LicenseRequest_ContentIdentification)
	licenseRequest.Msg.ContentId.CencId = new(LicenseRequest_ContentIdentification_CENC)

	// this is probably really bad for the GC but protobuf uses pointers for optional
	// fields so it is necessary and this is not a long running program
	{
		v := SignedLicenseRequest_LICENSE_REQUEST
		licenseRequest.Type = &v
	}

	licenseRequest.Msg.ContentId.CencId.Pssh = &c.widevineCencHeader

	{
		v := LicenseType_DEFAULT
		licenseRequest.Msg.ContentId.CencId.LicenseType = &v
	}

	licenseRequest.Msg.ContentId.CencId.RequestId = c.sessionID[:]

	{
		v := LicenseRequest_NEW
		licenseRequest.Msg.Type = &v
	}

	{
		v := uint32(time.Now().Unix())
		licenseRequest.Msg.RequestTime = &v
	}

	{
		v := ProtocolVersion_CURRENT
		licenseRequest.Msg.ProtocolVersion = &v
	}

	{
		v := randUint32()
		licenseRequest.Msg.KeyControlNonce = &v
	}

	if c.privacyMode {
		pad := func(data []byte, blockSize int) []byte {
			padlen := blockSize - (len(data) % blockSize)
			if padlen == 0 {
				padlen = blockSize
			}
			return append(data, bytes.Repeat([]byte{byte(padlen)}, padlen)...)
		}
		const blockSize = 16

		var cidKey, cidIV [blockSize]byte
		_, err := rand.Read(cidKey[:])
		if err != nil {
			return nil, err
		}
		_, err = rand.Read(cidIV[:])
		if err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(cidKey[:])
		if err != nil {
			return nil, err
		}

		paddedClientID := pad(c.clientID, blockSize)
		encryptedClientID := make([]byte, len(paddedClientID))
		cipher.NewCBCEncrypter(block, cidIV[:]).CryptBlocks(encryptedClientID, paddedClientID)

		servicePublicKey, err := x509.ParsePKCS1PublicKey(c.signedDeviceCertificate.XDeviceCertificate.PublicKey)
		if err != nil {
			return nil, err
		}

		encryptedCIDKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, servicePublicKey, cidKey[:], nil)
		if err != nil {
			return nil, err
		}

		licenseRequest.Msg.EncryptedClientId = new(EncryptedClientIdentification)
		{
			v := string(c.signedDeviceCertificate.XDeviceCertificate.ServiceId)
			licenseRequest.Msg.EncryptedClientId.ServiceId = &v
		}
		licenseRequest.Msg.EncryptedClientId.ServiceCertificateSerialNumber = c.signedDeviceCertificate.XDeviceCertificate.SerialNumber
		licenseRequest.Msg.EncryptedClientId.EncryptedClientId = encryptedClientID
		licenseRequest.Msg.EncryptedClientId.EncryptedClientIdIv = cidIV[:]
		licenseRequest.Msg.EncryptedClientId.EncryptedPrivacyKey = encryptedCIDKey
	} else {
		licenseRequest.Msg.ClientId = new(ClientIdentification)
		if err := proto.Unmarshal(c.clientID, licenseRequest.Msg.ClientId); err != nil {
			return nil, err
		}
	}

	{
		data, err := proto.Marshal(licenseRequest.Msg)
		if err != nil {
			return nil, err
		}
		hash := sha1.Sum(data)
		if licenseRequest.Signature, err = rsa.SignPSS(rand.Reader, c.privateKey, crypto.SHA1, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return nil, err
		}
	}

	return proto.Marshal(&licenseRequest)
}

// Retrieves the keys from the license response data.  These keys can be
// used to decrypt the DASH-MP4.
func (c *CDM) GetLicenseKeys(licenseRequest []byte, licenseResponse []byte) (keys []Key, err error) {
	var license SignedLicense
	if err = proto.Unmarshal(licenseResponse, &license); err != nil {
		return
	}

	var licenseRequestParsed SignedLicenseRequest
	if err = proto.Unmarshal(licenseRequest, &licenseRequestParsed); err != nil {
		return
	}
	licenseRequestMsg, err := proto.Marshal(licenseRequestParsed.Msg)
	if err != nil {
		return
	}

	sessionKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, c.privateKey, license.SessionKey, nil)
	if err != nil {
		return
	}

	sessionKeyBlock, err := aes.NewCipher(sessionKey)
	if err != nil {
		return
	}

	encryptionKey := []byte{1, 'E', 'N', 'C', 'R', 'Y', 'P', 'T', 'I', 'O', 'N', 0}
	encryptionKey = append(encryptionKey, licenseRequestMsg...)
	encryptionKey = append(encryptionKey, []byte{0, 0, 0, 0x80}...)

	//Create new CMAC with the session key
	mac := cmac.New(sessionKeyBlock)
	mac.Write(encryptionKey)
	encryptionKeyCmac := mac.Sum(nil)

	encryptionKeyCipher, err := aes.NewCipher(encryptionKeyCmac)
	if err != nil {
		return
	}

	unpad := func(b []byte) []byte {
		if len(b) == 0 {
			return b
		}
		// pks padding is designed so that the value of all the padding bytes is
		// the number of padding bytes repeated so to figure out how many
		// padding bytes there are we can just look at the value of the last
		// byte
		// i.e if there are 6 padding bytes then it will look at like
		// <data> 0x6 0x6 0x6 0x6 0x6 0x6
		count := int(b[len(b)-1])
		return b[0 : len(b)-count]
	}
	for _, key := range license.Msg.Key {
		decrypter := cipher.NewCBCDecrypter(encryptionKeyCipher, key.Iv)
		decryptedKey := make([]byte, len(key.Key))
		decrypter.CryptBlocks(decryptedKey, key.Key)
		keys = append(keys, Key{
			ID:    key.Id,
			Type:  *key.Type,
			Value: unpad(decryptedKey),
		})
	}

	return
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	max := int64(math.MaxInt64) - (int64(math.MaxInt64) % int64(n))
	v, err := randUint64()
	if err != nil {
		return 0
	}
	for v >= uint64(max) {
		v, err = randUint64()
		if err != nil {
			return 0
		}
	}
	return int(v % uint64(n))
}

func randUint32() uint32 {
	v, err := randUint64()
	if err != nil {
		return 0
	}
	return uint32(v)
}

func randUint64() (uint64, error) {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}
