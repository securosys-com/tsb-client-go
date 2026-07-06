# Securosys TSB Go Client

Go client for Securosys TSB key management and key operation APIs.

The package name is `client` and the module path is:

```go
github.com/securosys-com/tsb-client-go
```

## Create A Client

Use `NewTSBClient` when you want to configure the client directly:

```go
package main

import (
	"log"

	tsb "github.com/securosys-com/tsb-client-go"
)

func main() {
	client, err := tsb.NewTSBClient("https://tsb.example.com", tsb.AuthStruct{
		AppName:  "my-application",
		AuthType: "TOKEN",
		BearerToken: "bearer-token",
		ApiKeys: tsb.ApiKeyTypes{
			KeyManagementToken: []string{"key-management-api-key"},
			KeyOperationToken:  []string{"key-operation-api-key"},
			ServiceToken:       []string{"service-api-key"},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = client
}
```

Use `NewClient` when you already have a `helpers.SecurosysConfig`.

## Authorization

The client supports three authorization modes through `AuthStruct.AuthType`.

`NONE` sends no bearer token and no client certificate. API keys are still sent when configured.

```go
client, err := tsb.NewTSBClient("https://tsb.example.com", tsb.AuthStruct{
	AppName:  "my-application",
	AuthType: "NONE",
	ApiKeys: tsb.ApiKeyTypes{
		KeyManagementToken: []string{"key-management-api-key"},
		KeyOperationToken:  []string{"key-operation-api-key"},
	},
})
```

`TOKEN` sends `Authorization: Bearer <token>`.

```go
client, err := tsb.NewTSBClient("https://tsb.example.com", tsb.AuthStruct{
	AppName:     "my-application",
	AuthType:    "TOKEN",
	BearerToken: "bearer-token",
	ApiKeys: tsb.ApiKeyTypes{
		KeyManagementToken: []string{"key-management-api-key"},
		KeyOperationToken:  []string{"key-operation-api-key"},
	},
})
```

`CERT` configures mutual TLS. You can provide certificate/key files:

```go
client, err := tsb.NewTSBClient("https://tsb.example.com", tsb.AuthStruct{
	AppName:  "my-application",
	AuthType: "CERT",
	CertPath: "/path/to/client.crt",
	KeyPath:  "/path/to/client.key",
	ApiKeys: tsb.ApiKeyTypes{
		KeyManagementToken: []string{"key-management-api-key"},
		KeyOperationToken:  []string{"key-operation-api-key"},
	},
})
```

Or PEM strings:

```go
client, err := tsb.NewTSBClient("https://tsb.example.com", tsb.AuthStruct{
	AppName:  "my-application",
	AuthType: "CERT",
	CertPEM:  certPEM,
	KeyPEM:   keyPEM,
	ApiKeys: tsb.ApiKeyTypes{
		KeyManagementToken: []string{"key-management-api-key"},
		KeyOperationToken:  []string{"key-operation-api-key"},
	},
})
```

API keys are optional from the client side. Add them when your TSB tenant or endpoint is configured to require API keys. When configured, API keys are sent as `X-API-KEY`. The client chooses the API key group by operation:

- key management operations use `KeyManagementToken`
- sign, verify, encrypt, decrypt, wrap, unwrap, block, unblock, certificates, and requests use `KeyOperationToken`
- random generation uses `ServiceToken`

If multiple API keys are configured for a group, the client rolls over to the next one when TSB returns unauthorized error code `631`.

## Running Tests

The test suite includes live TSB integration tests. Tests that need TSB read configuration from environment variables and skip when required values are missing.

Create a local `.env` file:

```sh
export TSB_URL="https://engineering.securosys.com/tsb-demo"

# TOKEN auth. Leave commented when using NONE auth or CERT auth.
# export TSB_BEARER_TOKEN=""

# CERT auth using PEM content. Set both values together.
# export TSB_CERT_PEM=""
# export TSB_KEY_PEM=""

# CERT auth using files. Set both values together.
# export TSB_CERT_PATH=""
# export TSB_KEY_PATH=""

# Optional API keys. Fill these only when your TSB setup requires API keys.
export TSB_SERVICE_TOKEN=""
export TSB_KEY_MANAGEMENT_TOKEN=""
export TSB_KEY_OPERATION_TOKEN=""
export TSB_APPROVER_TOKEN=""
export TSB_APPROVER_KEY_MANAGEMENT_TOKEN=""
```

Load the environment and run tests:

```sh
set -a
source .env
set +a
go test -v ./...
```

Run a single test:

```sh
go test -v ./... -run TestCreateSignVerifyAllAlgorithmsAndDeleteKeyWithTSB
```

Authentication selection in tests:

- if `TSB_BEARER_TOKEN` is set, tests use `TOKEN` auth
- else if `TSB_CERT_PEM` and `TSB_KEY_PEM` are set, tests use `CERT` auth from PEM values
- else if `TSB_CERT_PATH` and `TSB_KEY_PATH` are set, tests use `CERT` auth from files
- otherwise tests use `NONE` auth

The integration tests create temporary keys with labels prefixed by `go-client-test-` and delete them after each test.

## Common Helpers

Most examples below create extractable test keys. For production, choose attributes and policy deliberately.

```go
func keyAttributes() map[string]bool {
	return map[string]bool{
		"decrypt":     true,
		"encrypt":     true,
		"extractable": true,
		"sign":        true,
		"unwrap":      true,
		"verify":      true,
		"wrap":        true,
		"destroyable": true,
	}
}
```

Supported key attributes:

- `encrypt`: if true, the key can encrypt data. This attribute is only supported for symmetric keys.
- `decrypt`: if true, the key can decrypt data.
- `verify`: if true, the key can verify signatures. This attribute is only supported for symmetric keys.
- `sign`: if true, the key can sign.
- `wrap`: if true, the key can wrap another key. This attribute is only supported for symmetric keys.
- `unwrap`: if true, the key can unwrap keys.
- `derive`: if true, it is possible to derive from this key. Default: `false`.
- `bip32`: if true, key derivation uses BIP32 / SLIP10. This can only be true when the key algorithm is `EC` or `ED` and `derive` is true. Default: `false`.
- `slip10`: if true, key derivation uses SLIP-0010. This can only be true when the key algorithm is `EC` or `ED` and `derive` is true. Default: `false`.
- `extractable`: if true, the key is extractable. This can only be true for keys without smart key attributes. Default: `false`.
- `modifiable`: if true, the key can be modified. This attribute applies only to the key attributes, not to SKA policy. Default: `true`.
- `destroyable`: if true, the key can be deleted. Default: `false`.
- `sensitive`: if true, the key is sensitive. To export a key, `sensitive` must be false.
- `copyable`: if true, the encrypted key can be stored in external memory. Default: `false`.

Payloads passed to sign, verify, encrypt, and decrypt are base64 strings.

## Sign And Verify

```go
ctx := context.Background()
password := ""
payload := base64.StdEncoding.EncodeToString([]byte("message to sign"))

label, err := client.CreateOrUpdateKey(
	"example-ec-sign-key",
	password,
	keyAttributes(),
	"EC",
	0,
	nil,
	"1.2.840.10045.3.1.7", // P-256
	false,
)
if err != nil {
	log.Fatal(err)
}
defer client.RemoveKey(label)

signature, status, err := client.Sign(
	ctx,
	label,
	password,
	payload,
	"UNSPECIFIED",
	tsb.SignatureAlgorithmSHA256WithECDSA,
	tsb.SignatureTypeRAW,
)
if err != nil {
	log.Fatalf("sign failed with status %d: %v", status, err)
}

valid, status, err := client.Verify(
	ctx,
	label,
	password,
	payload,
	tsb.SignatureAlgorithmSHA256WithECDSA,
	signature.Signature,
)
if err != nil {
	log.Fatalf("verify failed with status %d: %v", status, err)
}
log.Printf("signature valid: %t", valid)
```

For `NONESHA*` algorithms, hash the payload before calling `Sign` and `Verify` using the matching SHA algorithm. For example, `NONESHA256_WITH_RSA` expects a SHA-256 digest as the payload. For `NONE_WITH_*`, pass the digest expected by your TSB/signature configuration.

## Encrypt And Decrypt

```go
ctx := context.Background()
password := ""
payload := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

label, err := client.CreateOrUpdateKey(
	"example-aes-encrypt-key",
	password,
	keyAttributes(),
	"AES",
	256,
	nil,
	"",
	false,
)
if err != nil {
	log.Fatal(err)
}
defer client.RemoveKey(label)

encrypted, status, err := client.Encrypt(
	ctx,
	label,
	password,
	payload,
	tsb.CipherAlgorithmAESGCM,
	128,
	"",
)
if err != nil {
	log.Fatalf("encrypt failed with status %d: %v", status, err)
}

iv := ""
if encrypted.InitializationVector != nil {
	iv = *encrypted.InitializationVector
}

decrypted, status, err := client.Decrypt(
	ctx,
	label,
	password,
	encrypted.EncryptedPayload,
	iv,
	tsb.CipherAlgorithmAESGCM,
	128,
	"",
)
if err != nil {
	log.Fatalf("decrypt failed with status %d: %v", status, err)
}
log.Printf("decrypted payload: %s", decrypted.Payload)
```

Use tag length `128` for `AES_GCM` unless your integration needs a different supported tag length. Use `-1` for algorithms where no tag length should be sent.

For `RSA_NO_PADDING`, decrypt returns the full RSA block. The original plaintext is right-aligned and zero-padded on the left.

## Wrap And Unwrap

```go
ctx := context.Background()
password := ""

wrapKey, err := client.CreateOrUpdateKey(
	"example-aes-wrap-key",
	password,
	keyAttributes(),
	"AES",
	256,
	nil,
	"",
	false,
)
if err != nil {
	log.Fatal(err)
}
defer client.RemoveKey(wrapKey)

keyToWrap, err := client.CreateOrUpdateKey(
	"example-aes-key-to-wrap",
	password,
	keyAttributes(),
	"AES",
	256,
	nil,
	"",
	false,
)
if err != nil {
	log.Fatal(err)
}
defer client.RemoveKey(keyToWrap)
defer client.RemoveKey("example-aes-unwrapped-key")

wrapped, status, err := client.Wrap(
	wrapKey,
	password,
	keyToWrap,
	password,
	tsb.WrapMethodAES,
)
if err != nil {
	log.Fatalf("wrap failed with status %d: %v", status, err)
}

status, err = client.UnWrap(
	wrapped.WrappedKey,
	"example-aes-unwrapped-key",
	keyAttributes(),
	wrapKey,
	password,
	tsb.WrapMethodAES,
	nil,
)
if err != nil {
	log.Fatalf("unwrap failed with status %d: %v", status, err)
}

unwrapped, err := client.GetKey(ctx, "example-aes-unwrapped-key", password)
if err != nil {
	log.Fatal(err)
}
log.Printf("unwrapped key algorithm: %s", unwrapped.Algorithm)
```

The unwrap target label must be different from the source key label.

## Supported Key Types

- `EC`
- `ED`
- `RSA`
- `DSA`
- `BLS`
- `AES`
- `ChaCha20`
- `Camellia`
- `TDEA`

## Signature Types

- `DER`
- `ETH`
- `RAW`

## Signature Algorithms

RSA:

- `SHA224_WITH_RSA_PSS`
- `SHA256_WITH_RSA_PSS`
- `SHA384_WITH_RSA_PSS`
- `SHA512_WITH_RSA_PSS`
- `NONE_WITH_RSA`
- `NONE_WITH_RSA_PSS`
- `SHA224_WITH_RSA`
- `SHA256_WITH_RSA`
- `SHA384_WITH_RSA`
- `SHA512_WITH_RSA`
- `NONESHA224_WITH_RSA`
- `NONESHA256_WITH_RSA`
- `NONESHA384_WITH_RSA`
- `NONESHA512_WITH_RSA`
- `NONESHA224_WITH_RSA_PSS`
- `NONESHA256_WITH_RSA_PSS`
- `NONESHA384_WITH_RSA_PSS`
- `NONESHA512_WITH_RSA_PSS`
- `SHA1_WITH_RSA`
- `NONESHA1_WITH_RSA`
- `SHA1_WITH_RSA_PSS`

EC:

- `NONE_WITH_ECDSA`
- `SHA1_WITH_ECDSA`
- `SHA224_WITH_ECDSA`
- `SHA256_WITH_ECDSA`
- `DOUBLE_SHA256_WITH_ECDSA`
- `SHA384_WITH_ECDSA`
- `SHA512_WITH_ECDSA`
- `SHA3224_WITH_ECDSA`
- `SHA3256_WITH_ECDSA`
- `SHA3384_WITH_ECDSA`
- `SHA3512_WITH_ECDSA`
- `SHA256_WITH_ECDSA_DETERMINISTIC`
- `KECCAK224_WITH_ECDSA`
- `KECCAK256_WITH_ECDSA`
- `KECCAK384_WITH_ECDSA`
- `KECCAK512_WITH_ECDSA`

DSA:

- `NONE_WITH_DSA`
- `SHA224_WITH_DSA`
- `SHA256_WITH_DSA`
- `SHA384_WITH_DSA`
- `SHA512_WITH_DSA`
- `SHA1_WITH_DSA`

Other:

- `EDDSA`
- `BLS`

## Encrypt And Decrypt Algorithms

RSA:

- `RSA_PADDING_OAEP_WITH_SHA512`
- `RSA`
- `RSA_PADDING_OAEP_WITH_SHA224`
- `RSA_PADDING_OAEP_WITH_SHA256`
- `RSA_PADDING_OAEP_WITH_SHA1`
- `RSA_PADDING_OAEP`
- `RSA_PADDING_OAEP_WITH_SHA384`
- `RSA_PADDING_PKCS`
- `RSA_NO_PADDING`

AES:

- `AES_GCM`
- `AES_CTR`
- `AES_ECB`
- `AES_CBC_NO_PADDING`
- `AES`

ChaCha20:

- `CHACHA20`
- `CHACHA20_AEAD`

Camellia:

- `CAMELLIA`
- `CAMELLIA_CBC_NO_PADDING`
- `CAMELLIA_ECB`

TDEA:

- `TDEA_CBC`
- `TDEA_ECB`
- `TDEA_CBC_NO_PADDING`

## Wrap Methods

AES wrap methods:

- `AES_WRAP`
- `AES_WRAP_DSA`
- `AES_WRAP_EC`
- `AES_WRAP_ED`
- `AES_WRAP_RSA`
- `AES_WRAP_BLS`
- `AES_WRAP_PAD`
- `AES_WRAP_PAD_DSA`
- `AES_WRAP_PAD_EC`
- `AES_WRAP_PAD_ED`
- `AES_WRAP_PAD_RSA`
- `AES_WRAP_PAD_BLS`

RSA wrap methods:

- `RSA_WRAP_PAD`
- `RSA_WRAP_OAEP`

## Payload Types

- `UNSPECIFIED`
- `ISO_20022`
- `PDF`
- `BTC`
- `ETH`

## Tag Lengths

- `0`
- `64`
- `96`
- `104`
- `112`
- `120`
- `128`

## Acknowledgements

This README was created with help from ChatGPT Codex.

## License

This project is licensed under the [Apache 2.0](./LICENSE) license.
