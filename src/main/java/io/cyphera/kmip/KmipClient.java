/*
 * Copyright 2026 Horizon Digital Engineering LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cyphera.kmip;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

/**
 * KMIP client -- connects to any KMIP 1.4 server via mTLS.
 *
 * <p>Usage:
 * <pre>
 * KmipClient client = new KmipClient.Builder()
 *     .host("kmip-server.corp.internal")
 *     .clientCert("/path/to/client.pem")
 *     .clientKey("/path/to/client-key.pem")
 *     .caCert("/path/to/ca.pem")
 *     .build();
 *
 * byte[] key = client.fetchKey("my-key-name");
 * // key is raw key bytes
 *
 * client.close();
 * </pre>
 */
public class KmipClient implements AutoCloseable {

    private final String host;
    private final int port;
    private final int timeout;
    private final SSLContext sslContext;
    private SSLSocket socket;

    private KmipClient(String host, int port, int timeout, SSLContext sslContext) {
        this.host = host;
        this.port = port;
        this.timeout = timeout;
        this.sslContext = sslContext;
    }

    /**
     * Locate keys by name.
     *
     * @param name key name to search for
     * @return list of unique identifiers
     */
    public List<String> locate(String name) throws IOException {
        byte[] request = Operations.buildLocateRequest(name);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseLocatePayload(response.payload).uniqueIdentifiers;
    }

    /**
     * Get key material by unique ID.
     *
     * @param uniqueId the unique identifier
     * @return parsed Get result with key material
     */
    public Operations.GetResult get(String uniqueId) throws IOException {
        byte[] request = Operations.buildGetRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseGetPayload(response.payload);
    }

    /**
     * Create a new symmetric key on the server.
     *
     * @param name      key name
     * @param algorithm algorithm name (e.g., "AES")
     * @param length    key length in bits (e.g., 256)
     * @return parsed Create result with unique identifier
     */
    public Operations.CreateResult create(String name, String algorithm, int length) throws IOException {
        int algoEnum = resolveAlgorithm(algorithm);
        byte[] request = Operations.buildCreateRequest(name, algoEnum, length);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseCreatePayload(response.payload);
    }

    /**
     * Create a new AES-256 symmetric key on the server.
     */
    public Operations.CreateResult create(String name) throws IOException {
        return create(name, "AES", 256);
    }

    /**
     * Activate a key by unique ID.
     */
    public void activate(String uniqueId) throws IOException {
        byte[] request = Operations.buildActivateRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Destroy a key by unique ID.
     */
    public void destroy(String uniqueId) throws IOException {
        byte[] request = Operations.buildDestroyRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Check the status of a managed object.
     */
    public Operations.CheckResult check(String uniqueId) throws IOException {
        byte[] request = Operations.buildCheckRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseCheckPayload(response.payload);
    }

    /**
     * Create a new asymmetric key pair on the server.
     */
    public Operations.CreateKeyPairResult createKeyPair(String name, int algorithm, int length) throws IOException {
        byte[] request = Operations.buildCreateKeyPairRequest(name, algorithm, length);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseCreateKeyPairPayload(response.payload);
    }

    /**
     * Register existing key material on the server.
     */
    public Operations.CreateResult register(int objectType, byte[] material, String name, int algorithm, int length) throws IOException {
        byte[] request = Operations.buildRegisterRequest(objectType, material, name, algorithm, length);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseCreatePayload(response.payload);
    }

    /**
     * Re-key an existing key on the server.
     */
    public Operations.ReKeyResult reKey(String uniqueId) throws IOException {
        byte[] request = Operations.buildReKeyRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseReKeyPayload(response.payload);
    }

    /**
     * Derive a new key from an existing key.
     */
    public Operations.DeriveKeyResult deriveKey(String uniqueId, byte[] derivationData, String name, int length) throws IOException {
        byte[] request = Operations.buildDeriveKeyRequest(uniqueId, derivationData, name, length);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseDeriveKeyPayload(response.payload);
    }

    /**
     * Fetch all attributes of a managed object.
     */
    public Operations.GetResult getAttributes(String uniqueId) throws IOException {
        byte[] request = Operations.buildGetAttributesRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseGetPayload(response.payload);
    }

    /**
     * Fetch the list of attribute names for a managed object.
     */
    public List<String> getAttributeList(String uniqueId) throws IOException {
        byte[] request = Operations.buildGetAttributeListRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        if (response.payload == null) {
            return new ArrayList<>();
        }
        List<Ttlv.Item> attrs = Ttlv.findChildren(response.payload, Tag.ATTRIBUTE_NAME);
        List<String> names = new ArrayList<>();
        for (Ttlv.Item attr : attrs) {
            names.add(attr.stringValue());
        }
        return names;
    }

    /**
     * Add an attribute to a managed object.
     */
    public void addAttribute(String uniqueId, String name, String value) throws IOException {
        byte[] request = Operations.buildAddAttributeRequest(uniqueId, name, value);
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Modify an attribute of a managed object.
     */
    public void modifyAttribute(String uniqueId, String name, String value) throws IOException {
        byte[] request = Operations.buildModifyAttributeRequest(uniqueId, name, value);
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Delete an attribute from a managed object.
     */
    public void deleteAttribute(String uniqueId, String name) throws IOException {
        byte[] request = Operations.buildDeleteAttributeRequest(uniqueId, name);
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Obtain a lease for a managed object. Returns lease time in seconds.
     */
    public int obtainLease(String uniqueId) throws IOException {
        byte[] request = Operations.buildObtainLeaseRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        if (response.payload == null) return 0;
        Ttlv.Item lease = Ttlv.findChild(response.payload, Tag.LEASE_TIME);
        return lease != null ? lease.intValue() : 0;
    }

    /**
     * Revoke a managed object with the given reason code.
     */
    public void revoke(String uniqueId, int reason) throws IOException {
        byte[] request = Operations.buildRevokeRequest(uniqueId, reason);
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Archive a managed object.
     */
    public void archive(String uniqueId) throws IOException {
        byte[] request = Operations.buildArchiveRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Recover an archived managed object.
     */
    public void recover(String uniqueId) throws IOException {
        byte[] request = Operations.buildRecoverRequest(uniqueId);
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Query the server for supported operations and object types.
     */
    public Operations.QueryResult query() throws IOException {
        byte[] request = Operations.buildQueryRequest();
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseQueryPayload(response.payload);
    }

    /**
     * Poll the server.
     */
    public void poll() throws IOException {
        byte[] request = Operations.buildPollRequest();
        byte[] responseData = send(request);
        Operations.parseResponse(responseData);
    }

    /**
     * Discover the KMIP versions supported by the server.
     */
    public Operations.DiscoverVersionsResult discoverVersions() throws IOException {
        byte[] request = Operations.buildDiscoverVersionsRequest();
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseDiscoverVersionsPayload(response.payload);
    }

    /**
     * Encrypt data using a managed key.
     */
    public Operations.EncryptResult encrypt(String uniqueId, byte[] data) throws IOException {
        byte[] request = Operations.buildEncryptRequest(uniqueId, data);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseEncryptPayload(response.payload);
    }

    /**
     * Decrypt data using a managed key.
     */
    public Operations.DecryptResult decrypt(String uniqueId, byte[] data, byte[] nonce) throws IOException {
        byte[] request = Operations.buildDecryptRequest(uniqueId, data, nonce);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseDecryptPayload(response.payload);
    }

    /**
     * Sign data using a managed key.
     */
    public Operations.SignResult sign(String uniqueId, byte[] data) throws IOException {
        byte[] request = Operations.buildSignRequest(uniqueId, data);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseSignPayload(response.payload);
    }

    /**
     * Verify a signature using a managed key.
     */
    public Operations.SignatureVerifyResult signatureVerify(String uniqueId, byte[] data, byte[] signature) throws IOException {
        byte[] request = Operations.buildSignatureVerifyRequest(uniqueId, data, signature);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseSignatureVerifyPayload(response.payload);
    }

    /**
     * Compute a MAC using a managed key.
     */
    public Operations.MACResult mac(String uniqueId, byte[] data) throws IOException {
        byte[] request = Operations.buildMacRequest(uniqueId, data);
        byte[] responseData = send(request);
        Operations.Response response = Operations.parseResponse(responseData);
        return Operations.parseMacPayload(response.payload);
    }

    /**
     * Convenience: locate by name + get material in one call.
     *
     * @param name key name
     * @return raw key bytes
     */
    public byte[] fetchKey(String name) throws IOException {
        List<String> ids = locate(name);
        if (ids.isEmpty()) {
            throw new KmipException("KMIP: no key found with name \"" + name + "\"");
        }
        Operations.GetResult result = get(ids.get(0));
        if (result.keyMaterial == null) {
            throw new KmipException(
                "KMIP: key \"" + name + "\" (" + ids.get(0) + ") has no extractable material");
        }
        return result.keyMaterial;
    }

    /**
     * Close the TLS connection.
     */
    @Override
    public void close() {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // best effort
            }
            socket = null;
        }
    }

    // --- Private methods ---

    private byte[] send(byte[] request) throws IOException {
        SSLSocket sock = connect();
        OutputStream out = sock.getOutputStream();
        out.write(request);
        out.flush();

        InputStream in = sock.getInputStream();

        // Read the TTLV header (8 bytes) to determine response length
        byte[] header = readExact(in, 8);
        int valueLength = ByteBuffer.wrap(header, 4, 4).getInt();
        int totalLength = 8 + valueLength;

        byte[] response = new byte[totalLength];
        System.arraycopy(header, 0, response, 0, 8);
        byte[] body = readExact(in, valueLength);
        System.arraycopy(body, 0, response, 8, valueLength);

        return response;
    }

    private byte[] readExact(InputStream in, int length) throws IOException {
        byte[] buf = new byte[length];
        int offset = 0;
        while (offset < length) {
            int n = in.read(buf, offset, length - offset);
            if (n < 0) {
                throw new IOException("KMIP: connection closed before full response received");
            }
            offset += n;
        }
        return buf;
    }

    private SSLSocket connect() throws IOException {
        if (socket != null && !socket.isClosed()) {
            return socket;
        }
        try {
            socket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
            socket.setSoTimeout(timeout);
            socket.startHandshake();
            return socket;
        } catch (IOException e) {
            throw new IOException("KMIP connection failed: " + e.getMessage(), e);
        }
    }

    private static int resolveAlgorithm(String algorithm) {
        if (algorithm == null) return Tag.ALG_AES;
        switch (algorithm.toUpperCase()) {
            case "AES":         return Tag.ALG_AES;
            case "DES":         return Tag.ALG_DES;
            case "TRIPLEDES":
            case "3DES":        return Tag.ALG_TRIPLE_DES;
            case "RSA":         return Tag.ALG_RSA;
            case "DSA":         return Tag.ALG_DSA;
            case "ECDSA":       return Tag.ALG_ECDSA;
            case "HMACSHA1":    return Tag.ALG_HMAC_SHA1;
            case "HMACSHA256":  return Tag.ALG_HMAC_SHA256;
            case "HMACSHA384":  return Tag.ALG_HMAC_SHA384;
            case "HMACSHA512":  return Tag.ALG_HMAC_SHA512;
            default:            return Tag.ALG_AES;
        }
    }

    // --- Builder ---

    /**
     * Builder for KmipClient.
     */
    public static class Builder {
        private String host;
        private int port = 5696;
        private String clientCertPath;
        private String clientKeyPath;
        private String caCertPath;
        private int timeout = 10000;

        public Builder host(String host) { this.host = host; return this; }
        public Builder port(int port) { this.port = port; return this; }
        public Builder clientCert(String path) { this.clientCertPath = path; return this; }
        public Builder clientKey(String path) { this.clientKeyPath = path; return this; }
        public Builder caCert(String path) { this.caCertPath = path; return this; }
        public Builder timeout(int timeoutMs) { this.timeout = timeoutMs; return this; }

        public KmipClient build() {
            if (host == null) throw new IllegalArgumentException("host is required");
            if (clientCertPath == null) throw new IllegalArgumentException("clientCert is required");
            if (clientKeyPath == null) throw new IllegalArgumentException("clientKey is required");

            try {
                SSLContext ctx = buildSSLContext(clientCertPath, clientKeyPath, caCertPath);
                return new KmipClient(host, port, timeout, ctx);
            } catch (Exception e) {
                throw new KmipException("Failed to build SSL context: " + e.getMessage(), e);
            }
        }

        private static SSLContext buildSSLContext(String certPath, String keyPath, String caPath)
                throws Exception {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // Load client certificate
            byte[] certBytes = Files.readAllBytes(Path.of(certPath));
            Collection<? extends Certificate> certs = cf.generateCertificates(
                new ByteArrayInputStream(certBytes));

            // Load client private key (PKCS8 PEM)
            String keyPem = Files.readString(Path.of(keyPath));
            PrivateKey privateKey = loadPrivateKey(keyPem);

            // Build key store
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("client",
                privateKey,
                new char[0],
                certs.toArray(new Certificate[0]));

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);

            // Build trust store
            TrustManagerFactory tmf = null;
            if (caPath != null) {
                byte[] caBytes = Files.readAllBytes(Path.of(caPath));
                Collection<? extends Certificate> caCerts = cf.generateCertificates(
                    new ByteArrayInputStream(caBytes));

                KeyStore trustStore = KeyStore.getInstance("PKCS12");
                trustStore.load(null, null);
                int i = 0;
                for (Certificate ca : caCerts) {
                    trustStore.setCertificateEntry("ca-" + i++, ca);
                }

                tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);
            }

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(
                kmf.getKeyManagers(),
                tmf != null ? tmf.getTrustManagers() : null,
                null);
            return ctx;
        }

        private static PrivateKey loadPrivateKey(String pem) throws Exception {
            // Strip PEM headers/footers and decode
            String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

            byte[] der = Base64.getDecoder().decode(base64);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);

            // Try RSA first, then EC
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (Exception e) {
                try {
                    return KeyFactory.getInstance("EC").generatePrivate(spec);
                } catch (Exception e2) {
                    return KeyFactory.getInstance("DSA").generatePrivate(spec);
                }
            }
        }
    }
}
