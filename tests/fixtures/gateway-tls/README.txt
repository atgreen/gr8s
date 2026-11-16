Public, test-only TLS material. Never use these private keys outside tests.
server.crt is a self-signed P-256 certificate for example.test with digitalSignature
key usage. server.key matches it; other.key deliberately does not.
These tests check parsing and key compatibility, not trust or certificate expiry.
