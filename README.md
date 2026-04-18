# kmip-java

[![CI](https://github.com/cyphera-labs/kmip-java/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/kmip-java/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/kmip-java/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/kmip-java/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

KMIP client for Java — connect to any KMIP-compliant key management server.

Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix, HashiCorp Vault Enterprise, and any KMIP 1.4 server.

```xml
<dependency>
    <groupId>io.cyphera</groupId>
    <artifactId>kmip</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick Start

```java
import io.cyphera.kmip.KmipClient;

KmipClient client = new KmipClient.Builder()
    .host("kmip-server.corp.internal")
    .clientCert("/path/to/client.pem")
    .clientKey("/path/to/client-key.pem")
    .caCert("/path/to/ca.pem")
    .build();

// Fetch a key by name (locate + get in one call)
byte[] key = client.fetchKey("my-encryption-key");
// key is raw key bytes (e.g., 32 bytes for AES-256)

// Or step by step:
List<String> ids = client.locate("my-key");
Operations.GetResult result = client.get(ids.get(0));
// result.keyMaterial is byte[]

// Create a new AES-256 key on the server
Operations.CreateResult created = client.create("new-key-name", "AES", 256);
System.out.println(created.uniqueIdentifier);

client.close();
```

## Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Locate | `client.locate(name)` | Find keys by name, returns unique IDs |
| Get | `client.get(id)` | Fetch key material by unique ID |
| Create | `client.create(name, algo, length)` | Create a new symmetric key |
| Fetch | `client.fetchKey(name)` | Locate + Get in one call |

## Authentication

KMIP uses mutual TLS (mTLS). Provide:
- **Client certificate** — identifies your application to the KMS
- **Client private key** — proves ownership of the certificate
- **CA certificate** — validates the KMS server's certificate

```java
KmipClient client = new KmipClient.Builder()
    .host("kmip.corp.internal")
    .port(5696)                          // default KMIP port
    .clientCert("/etc/kmip/client.pem")
    .clientKey("/etc/kmip/client-key.pem")
    .caCert("/etc/kmip/ca.pem")
    .timeout(10000)                      // connection timeout (ms)
    .build();
```

## TTLV Codec

The low-level TTLV (Tag-Type-Length-Value) encoder/decoder is also available for advanced use:

```java
import io.cyphera.kmip.Ttlv;
import io.cyphera.kmip.Tag;

// Build custom KMIP messages
byte[] msg = Ttlv.encodeStructure(Tag.REQUEST_MESSAGE, ...);

// Parse raw KMIP responses
Ttlv.Item parsed = Ttlv.decodeTTLV(responseBytes);
```

## Supported KMS Servers

| Server | KMIP Version | Tested |
|--------|-------------|--------|
| Thales CipherTrust Manager | 1.x, 2.0 | Planned |
| IBM SKLM | 1.x, 2.0 | Planned |
| Entrust KeyControl | 1.x, 2.0 | Planned |
| Fortanix DSM | 2.0 | Planned |
| HashiCorp Vault Enterprise | 1.4 | Planned |
| PyKMIP (test server) | 1.0-2.0 | CI |

## Zero Dependencies

This library uses only Java standard library (`javax.net.ssl`, `java.security`, `java.nio`). No external dependencies.

## Status

Alpha. KMIP 1.4 operations: Locate, Get, Create.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
