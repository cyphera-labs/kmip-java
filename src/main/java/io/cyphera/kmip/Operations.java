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

import java.util.ArrayList;
import java.util.List;

import static io.cyphera.kmip.Ttlv.*;

/**
 * KMIP request/response builders and parsers for all 27 KMIP 1.4 operations.
 */
public final class Operations {

    /** Protocol version: KMIP 1.4 */
    public static final int PROTOCOL_MAJOR = 1;
    public static final int PROTOCOL_MINOR = 4;

    private Operations() { }

    // --- Response holders ---

    /** Parsed KMIP response. */
    public static final class Response {
        public final int operation;
        public final int resultStatus;
        public final int resultReason;
        public final String resultMessage;
        public final Ttlv.Item payload;

        public Response(int operation, int resultStatus, int resultReason,
                        String resultMessage, Ttlv.Item payload) {
            this.operation = operation;
            this.resultStatus = resultStatus;
            this.resultReason = resultReason;
            this.resultMessage = resultMessage;
            this.payload = payload;
        }
    }

    /** Parsed Locate response. */
    public static final class LocateResult {
        public final List<String> uniqueIdentifiers;

        public LocateResult(List<String> uniqueIdentifiers) {
            this.uniqueIdentifiers = uniqueIdentifiers;
        }
    }

    /** Parsed Get response. */
    public static final class GetResult {
        public final int objectType;
        public final String uniqueIdentifier;
        public final byte[] keyMaterial;

        public GetResult(int objectType, String uniqueIdentifier, byte[] keyMaterial) {
            this.objectType = objectType;
            this.uniqueIdentifier = uniqueIdentifier;
            this.keyMaterial = keyMaterial;
        }
    }

    /** Parsed Create response. */
    public static final class CreateResult {
        public final int objectType;
        public final String uniqueIdentifier;

        public CreateResult(int objectType, String uniqueIdentifier) {
            this.objectType = objectType;
            this.uniqueIdentifier = uniqueIdentifier;
        }
    }

    /** Parsed Check response. */
    public static final class CheckResult {
        public final String uniqueIdentifier;

        public CheckResult(String uniqueIdentifier) {
            this.uniqueIdentifier = uniqueIdentifier;
        }
    }

    /** Parsed ReKey response. */
    public static final class ReKeyResult {
        public final String uniqueIdentifier;

        public ReKeyResult(String uniqueIdentifier) {
            this.uniqueIdentifier = uniqueIdentifier;
        }
    }

    /** Parsed Encrypt response. */
    public static final class EncryptResult {
        public final byte[] data;
        public final byte[] nonce;

        public EncryptResult(byte[] data, byte[] nonce) {
            this.data = data;
            this.nonce = nonce;
        }
    }

    /** Parsed Decrypt response. */
    public static final class DecryptResult {
        public final byte[] data;

        public DecryptResult(byte[] data) {
            this.data = data;
        }
    }

    /** Parsed Sign response. */
    public static final class SignResult {
        public final byte[] signatureData;

        public SignResult(byte[] signatureData) {
            this.signatureData = signatureData;
        }
    }

    /** Parsed SignatureVerify response. */
    public static final class SignatureVerifyResult {
        public final boolean valid;

        public SignatureVerifyResult(boolean valid) {
            this.valid = valid;
        }
    }

    /** Parsed MAC response. */
    public static final class MACResult {
        public final byte[] macData;

        public MACResult(byte[] macData) {
            this.macData = macData;
        }
    }

    /** Parsed Query response. */
    public static final class QueryResult {
        public final List<Integer> operations;
        public final List<Integer> objectTypes;

        public QueryResult(List<Integer> operations, List<Integer> objectTypes) {
            this.operations = operations;
            this.objectTypes = objectTypes;
        }
    }

    /** Parsed DiscoverVersions response. */
    public static final class DiscoverVersionsResult {
        public final List<int[]> versions;

        public DiscoverVersionsResult(List<int[]> versions) {
            this.versions = versions;
        }
    }

    /** Parsed DeriveKey response. */
    public static final class DeriveKeyResult {
        public final String uniqueIdentifier;

        public DeriveKeyResult(String uniqueIdentifier) {
            this.uniqueIdentifier = uniqueIdentifier;
        }
    }

    /** Parsed CreateKeyPair response. */
    public static final class CreateKeyPairResult {
        public final String privateKeyUid;
        public final String publicKeyUid;

        public CreateKeyPairResult(String privateKeyUid, String publicKeyUid) {
            this.privateKeyUid = privateKeyUid;
            this.publicKeyUid = publicKeyUid;
        }
    }

    // --- Request builders ---

    /** Build the request header (included in every request). */
    static byte[] buildRequestHeader(int batchCount) {
        return buildRequestHeader(batchCount, null);
    }

    /** Build the request header with optional credential authentication. */
    static byte[] buildRequestHeader(int batchCount, Credential credential) {
        if (credential == null) {
            return encodeStructure(Tag.REQUEST_HEADER,
                encodeStructure(Tag.PROTOCOL_VERSION,
                    encodeInteger(Tag.PROTOCOL_VERSION_MAJOR, PROTOCOL_MAJOR),
                    encodeInteger(Tag.PROTOCOL_VERSION_MINOR, PROTOCOL_MINOR)
                ),
                encodeInteger(Tag.BATCH_COUNT, batchCount)
            );
        }
        // KMIP Authentication structure: 0x42000C -> Credential(0x420023)
        //   -> CredentialType(0x420024) + CredentialValue(0x420025)
        //     -> Username(0x420099) + Password(0x4200A1)
        byte[] authStructure = encodeStructure(Tag.AUTHENTICATION,
            encodeStructure(Tag.CREDENTIAL,
                encodeEnum(Tag.CREDENTIAL_TYPE, Tag.CREDENTIAL_TYPE_USERNAME_PASSWORD),
                encodeStructure(Tag.CREDENTIAL_VALUE,
                    encodeTextString(Tag.USERNAME, credential.getUsername()),
                    encodeTextString(Tag.PASSWORD, credential.getPassword())
                )
            )
        );
        return encodeStructure(Tag.REQUEST_HEADER,
            encodeStructure(Tag.PROTOCOL_VERSION,
                encodeInteger(Tag.PROTOCOL_VERSION_MAJOR, PROTOCOL_MAJOR),
                encodeInteger(Tag.PROTOCOL_VERSION_MINOR, PROTOCOL_MINOR)
            ),
            authStructure,
            encodeInteger(Tag.BATCH_COUNT, batchCount)
        );
    }

    /** Build a Locate request -- find keys by name. */
    public static byte[] buildLocateRequest(String name) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeStructure(Tag.ATTRIBUTE,
                encodeTextString(Tag.ATTRIBUTE_NAME, "Name"),
                encodeStructure(Tag.ATTRIBUTE_VALUE,
                    encodeTextString(Tag.NAME_VALUE, name),
                    encodeEnum(Tag.NAME_TYPE, Tag.NAME_TYPE_UNINTERPRETED_TEXT_STRING)
                )
            )
        );

        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_LOCATE),
            payload
        );

        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a Get request -- fetch key material by unique ID. */
    public static byte[] buildGetRequest(String uniqueId) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId)
        );

        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_GET),
            payload
        );

        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a Create request -- create a new symmetric key. */
    public static byte[] buildCreateRequest(String name, int algorithm, int length) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeEnum(Tag.OBJECT_TYPE, Tag.OBJ_SYMMETRIC_KEY),
            encodeStructure(Tag.TEMPLATE_ATTRIBUTE,
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                    encodeEnum(Tag.ATTRIBUTE_VALUE, algorithm)
                ),
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Cryptographic Length"),
                    encodeInteger(Tag.ATTRIBUTE_VALUE, length)
                ),
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
                    encodeInteger(Tag.ATTRIBUTE_VALUE, Tag.USAGE_ENCRYPT | Tag.USAGE_DECRYPT)
                ),
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Name"),
                    encodeStructure(Tag.ATTRIBUTE_VALUE,
                        encodeTextString(Tag.NAME_VALUE, name),
                        encodeEnum(Tag.NAME_TYPE, Tag.NAME_TYPE_UNINTERPRETED_TEXT_STRING)
                    )
                )
            )
        );

        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_CREATE),
            payload
        );

        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a request with just a UID in the payload. */
    static byte[] buildUidOnlyRequest(int operation, String uniqueId) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId)
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, operation),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a request with an empty payload. */
    static byte[] buildEmptyPayloadRequest(int operation) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD);
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, operation),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build an Activate request. */
    public static byte[] buildActivateRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_ACTIVATE, uniqueId);
    }

    /** Build a Destroy request. */
    public static byte[] buildDestroyRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_DESTROY, uniqueId);
    }

    /** Build a Check request. */
    public static byte[] buildCheckRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_CHECK, uniqueId);
    }

    /** Build a CreateKeyPair request. */
    public static byte[] buildCreateKeyPairRequest(String name, int algorithm, int length) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeStructure(Tag.TEMPLATE_ATTRIBUTE,
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                    encodeEnum(Tag.ATTRIBUTE_VALUE, algorithm)
                ),
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Cryptographic Length"),
                    encodeInteger(Tag.ATTRIBUTE_VALUE, length)
                ),
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
                    encodeInteger(Tag.ATTRIBUTE_VALUE, Tag.USAGE_SIGN | Tag.USAGE_VERIFY)
                ),
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Name"),
                    encodeStructure(Tag.ATTRIBUTE_VALUE,
                        encodeTextString(Tag.NAME_VALUE, name),
                        encodeEnum(Tag.NAME_TYPE, Tag.NAME_TYPE_UNINTERPRETED_TEXT_STRING)
                    )
                )
            )
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_CREATE_KEY_PAIR),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a Register request for a symmetric key. */
    public static byte[] buildRegisterRequest(int objectType, byte[] material, String name, int algorithm, int length) {
        List<byte[]> payloadChildren = new ArrayList<>();
        payloadChildren.add(encodeEnum(Tag.OBJECT_TYPE, objectType));
        payloadChildren.add(encodeStructure(Tag.SYMMETRIC_KEY,
            encodeStructure(Tag.KEY_BLOCK,
                encodeEnum(Tag.KEY_FORMAT_TYPE, Tag.KEY_FORMAT_RAW),
                encodeStructure(Tag.KEY_VALUE,
                    encodeByteString(Tag.KEY_MATERIAL, material)
                ),
                encodeEnum(Tag.CRYPTOGRAPHIC_ALGORITHM, algorithm),
                encodeInteger(Tag.CRYPTOGRAPHIC_LENGTH, length)
            )
        ));
        if (name != null && !name.isEmpty()) {
            payloadChildren.add(encodeStructure(Tag.TEMPLATE_ATTRIBUTE,
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Name"),
                    encodeStructure(Tag.ATTRIBUTE_VALUE,
                        encodeTextString(Tag.NAME_VALUE, name),
                        encodeEnum(Tag.NAME_TYPE, Tag.NAME_TYPE_UNINTERPRETED_TEXT_STRING)
                    )
                )
            ));
        }
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            payloadChildren.toArray(new byte[0][]));
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_REGISTER),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a ReKey request. */
    public static byte[] buildReKeyRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_RE_KEY, uniqueId);
    }

    /** Build a DeriveKey request. */
    public static byte[] buildDeriveKeyRequest(String uniqueId, byte[] derivationData, String name, int length) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeStructure(Tag.DERIVATION_PARAMETERS,
                encodeByteString(Tag.DERIVATION_DATA, derivationData)
            ),
            encodeStructure(Tag.TEMPLATE_ATTRIBUTE,
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Cryptographic Length"),
                    encodeInteger(Tag.ATTRIBUTE_VALUE, length)
                ),
                encodeStructure(Tag.ATTRIBUTE,
                    encodeTextString(Tag.ATTRIBUTE_NAME, "Name"),
                    encodeStructure(Tag.ATTRIBUTE_VALUE,
                        encodeTextString(Tag.NAME_VALUE, name),
                        encodeEnum(Tag.NAME_TYPE, Tag.NAME_TYPE_UNINTERPRETED_TEXT_STRING)
                    )
                )
            )
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_DERIVE_KEY),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a GetAttributes request. */
    public static byte[] buildGetAttributesRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_GET_ATTRIBUTES, uniqueId);
    }

    /** Build a GetAttributeList request. */
    public static byte[] buildGetAttributeListRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_GET_ATTRIBUTE_LIST, uniqueId);
    }

    /** Build an AddAttribute request. */
    public static byte[] buildAddAttributeRequest(String uniqueId, String attrName, String attrValue) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeStructure(Tag.ATTRIBUTE,
                encodeTextString(Tag.ATTRIBUTE_NAME, attrName),
                encodeTextString(Tag.ATTRIBUTE_VALUE, attrValue)
            )
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_ADD_ATTRIBUTE),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a ModifyAttribute request. */
    public static byte[] buildModifyAttributeRequest(String uniqueId, String attrName, String attrValue) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeStructure(Tag.ATTRIBUTE,
                encodeTextString(Tag.ATTRIBUTE_NAME, attrName),
                encodeTextString(Tag.ATTRIBUTE_VALUE, attrValue)
            )
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_MODIFY_ATTRIBUTE),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a DeleteAttribute request. */
    public static byte[] buildDeleteAttributeRequest(String uniqueId, String attrName) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeStructure(Tag.ATTRIBUTE,
                encodeTextString(Tag.ATTRIBUTE_NAME, attrName)
            )
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_DELETE_ATTRIBUTE),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build an ObtainLease request. */
    public static byte[] buildObtainLeaseRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_OBTAIN_LEASE, uniqueId);
    }

    /** Build a Revoke request with a revocation reason. */
    public static byte[] buildRevokeRequest(String uniqueId, int reason) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeStructure(Tag.REVOCATION_REASON,
                encodeEnum(Tag.REVOCATION_REASON_CODE, reason)
            )
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_REVOKE),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build an Archive request. */
    public static byte[] buildArchiveRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_ARCHIVE, uniqueId);
    }

    /** Build a Recover request. */
    public static byte[] buildRecoverRequest(String uniqueId) {
        return buildUidOnlyRequest(Tag.OP_RECOVER, uniqueId);
    }

    /** Build a Query request. */
    public static byte[] buildQueryRequest() {
        return buildEmptyPayloadRequest(Tag.OP_QUERY);
    }

    /** Build a Poll request. */
    public static byte[] buildPollRequest() {
        return buildEmptyPayloadRequest(Tag.OP_POLL);
    }

    /** Build a DiscoverVersions request. */
    public static byte[] buildDiscoverVersionsRequest() {
        return buildEmptyPayloadRequest(Tag.OP_DISCOVER_VERSIONS);
    }

    /** Build an Encrypt request. */
    public static byte[] buildEncryptRequest(String uniqueId, byte[] data) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeByteString(Tag.DATA, data)
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_ENCRYPT),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a Decrypt request. */
    public static byte[] buildDecryptRequest(String uniqueId, byte[] data, byte[] nonce) {
        List<byte[]> payloadChildren = new ArrayList<>();
        payloadChildren.add(encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId));
        payloadChildren.add(encodeByteString(Tag.DATA, data));
        if (nonce != null && nonce.length > 0) {
            payloadChildren.add(encodeByteString(Tag.IV_COUNTER_NONCE, nonce));
        }
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            payloadChildren.toArray(new byte[0][]));
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_DECRYPT),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a Sign request. */
    public static byte[] buildSignRequest(String uniqueId, byte[] data) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeByteString(Tag.DATA, data)
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_SIGN),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a SignatureVerify request. */
    public static byte[] buildSignatureVerifyRequest(String uniqueId, byte[] data, byte[] signature) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeByteString(Tag.DATA, data),
            encodeByteString(Tag.SIGNATURE_DATA, signature)
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_SIGNATURE_VERIFY),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    /** Build a MAC request. */
    public static byte[] buildMacRequest(String uniqueId, byte[] data) {
        byte[] payload = encodeStructure(Tag.REQUEST_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, uniqueId),
            encodeByteString(Tag.DATA, data)
        );
        byte[] batchItem = encodeStructure(Tag.BATCH_ITEM,
            encodeEnum(Tag.OPERATION, Tag.OP_MAC),
            payload
        );
        return encodeStructure(Tag.REQUEST_MESSAGE,
            buildRequestHeader(1),
            batchItem
        );
    }

    // --- Response parsing ---

    /**
     * Parse a KMIP response message.
     *
     * @param data raw TTLV response bytes
     * @return parsed Response
     * @throws KmipException if the response indicates failure
     */
    public static Response parseResponse(byte[] data) {
        Ttlv.Item msg = decodeTTLV(data);
        if (msg.tag != Tag.RESPONSE_MESSAGE) {
            throw new KmipException(
                String.format("Expected ResponseMessage (0x42007B), got 0x%06X", msg.tag));
        }

        Ttlv.Item batchItem = findChild(msg, Tag.BATCH_ITEM);
        if (batchItem == null) {
            throw new KmipException("No BatchItem in response");
        }

        Ttlv.Item operationItem = findChild(batchItem, Tag.OPERATION);
        Ttlv.Item statusItem = findChild(batchItem, Tag.RESULT_STATUS);
        Ttlv.Item reasonItem = findChild(batchItem, Tag.RESULT_REASON);
        Ttlv.Item messageItem = findChild(batchItem, Tag.RESULT_MESSAGE);
        Ttlv.Item payloadItem = findChild(batchItem, Tag.RESPONSE_PAYLOAD);

        int operation = operationItem != null ? operationItem.intValue() : 0;
        // M7: Missing ResultStatus must not default to 0 (Success) — throw instead
        if (statusItem == null) {
            throw new KmipException("KMIP: response missing ResultStatus");
        }
        int resultStatus = statusItem.intValue();
        int resultReason = reasonItem != null ? reasonItem.intValue() : 0;
        String resultMessage = messageItem != null ? messageItem.stringValue() : null;

        if (resultStatus != Tag.STATUS_SUCCESS) {
            String errMsg = resultMessage != null
                ? resultMessage
                : "KMIP operation failed (status=" + resultStatus + ")";
            KmipException err = new KmipException(errMsg);
            err.resultStatus = resultStatus;
            err.resultReason = resultReason;
            throw err;
        }

        return new Response(operation, resultStatus, resultReason, resultMessage, payloadItem);
    }

    /** Parse a Locate response payload. */
    public static LocateResult parseLocatePayload(Ttlv.Item payload) {
        // M6: Null payload check
        if (payload == null) {
            return new LocateResult(new ArrayList<>());
        }
        List<Ttlv.Item> ids = findChildren(payload, Tag.UNIQUE_IDENTIFIER);
        List<String> result = new ArrayList<>();
        for (Ttlv.Item id : ids) {
            result.add(id.stringValue());
        }
        return new LocateResult(result);
    }

    /** Parse a Get response payload. */
    public static GetResult parseGetPayload(Ttlv.Item payload) {
        // M6: Null payload check
        if (payload == null) {
            return new GetResult(0, null, null);
        }
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        Ttlv.Item objType = findChild(payload, Tag.OBJECT_TYPE);

        // Navigate: SymmetricKey -> KeyBlock -> KeyValue -> KeyMaterial
        byte[] keyMaterial = null;
        Ttlv.Item symKey = findChild(payload, Tag.SYMMETRIC_KEY);
        if (symKey != null) {
            Ttlv.Item keyBlock = findChild(symKey, Tag.KEY_BLOCK);
            if (keyBlock != null) {
                Ttlv.Item keyValue = findChild(keyBlock, Tag.KEY_VALUE);
                if (keyValue != null) {
                    Ttlv.Item material = findChild(keyValue, Tag.KEY_MATERIAL);
                    if (material != null) {
                        keyMaterial = material.bytesValue();
                    }
                }
            }
        }

        return new GetResult(
            objType != null ? objType.intValue() : 0,
            uid != null ? uid.stringValue() : null,
            keyMaterial
        );
    }

    /** Parse a Create response payload. */
    public static CreateResult parseCreatePayload(Ttlv.Item payload) {
        // M6: Null payload check
        if (payload == null) {
            return new CreateResult(0, null);
        }
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        Ttlv.Item objType = findChild(payload, Tag.OBJECT_TYPE);
        return new CreateResult(
            objType != null ? objType.intValue() : 0,
            uid != null ? uid.stringValue() : null
        );
    }

    /** Parse a Check response payload. */
    public static CheckResult parseCheckPayload(Ttlv.Item payload) {
        if (payload == null) return new CheckResult(null);
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        return new CheckResult(uid != null ? uid.stringValue() : null);
    }

    /** Parse a ReKey response payload. */
    public static ReKeyResult parseReKeyPayload(Ttlv.Item payload) {
        if (payload == null) return new ReKeyResult(null);
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        return new ReKeyResult(uid != null ? uid.stringValue() : null);
    }

    /** Parse an Encrypt response payload. */
    public static EncryptResult parseEncryptPayload(Ttlv.Item payload) {
        if (payload == null) return new EncryptResult(null, null);
        Ttlv.Item data = findChild(payload, Tag.DATA);
        Ttlv.Item nonce = findChild(payload, Tag.IV_COUNTER_NONCE);
        return new EncryptResult(
            data != null ? data.bytesValue() : null,
            nonce != null ? nonce.bytesValue() : null
        );
    }

    /** Parse a Decrypt response payload. */
    public static DecryptResult parseDecryptPayload(Ttlv.Item payload) {
        if (payload == null) return new DecryptResult(null);
        Ttlv.Item data = findChild(payload, Tag.DATA);
        return new DecryptResult(data != null ? data.bytesValue() : null);
    }

    /** Parse a Sign response payload. */
    public static SignResult parseSignPayload(Ttlv.Item payload) {
        if (payload == null) return new SignResult(null);
        Ttlv.Item sig = findChild(payload, Tag.SIGNATURE_DATA);
        return new SignResult(sig != null ? sig.bytesValue() : null);
    }

    /** Parse a SignatureVerify response payload. */
    public static SignatureVerifyResult parseSignatureVerifyPayload(Ttlv.Item payload) {
        if (payload == null) return new SignatureVerifyResult(false);
        Ttlv.Item indicator = findChild(payload, Tag.VALIDITY_INDICATOR);
        // 0 = Valid, 1 = Invalid
        return new SignatureVerifyResult(indicator != null && indicator.intValue() == 0);
    }

    /** Parse a MAC response payload. */
    public static MACResult parseMacPayload(Ttlv.Item payload) {
        if (payload == null) return new MACResult(null);
        Ttlv.Item macData = findChild(payload, Tag.MAC_DATA);
        return new MACResult(macData != null ? macData.bytesValue() : null);
    }

    /** Parse a Query response payload. */
    public static QueryResult parseQueryPayload(Ttlv.Item payload) {
        List<Integer> ops = new ArrayList<>();
        List<Integer> objTypes = new ArrayList<>();
        if (payload != null) {
            for (Ttlv.Item op : findChildren(payload, Tag.OPERATION)) {
                ops.add(op.intValue());
            }
            for (Ttlv.Item ot : findChildren(payload, Tag.OBJECT_TYPE)) {
                objTypes.add(ot.intValue());
            }
        }
        return new QueryResult(ops, objTypes);
    }

    /** Parse a DiscoverVersions response payload. */
    public static DiscoverVersionsResult parseDiscoverVersionsPayload(Ttlv.Item payload) {
        List<int[]> versions = new ArrayList<>();
        if (payload != null) {
            for (Ttlv.Item v : findChildren(payload, Tag.PROTOCOL_VERSION)) {
                Ttlv.Item major = findChild(v, Tag.PROTOCOL_VERSION_MAJOR);
                Ttlv.Item minor = findChild(v, Tag.PROTOCOL_VERSION_MINOR);
                versions.add(new int[]{
                    major != null ? major.intValue() : 0,
                    minor != null ? minor.intValue() : 0
                });
            }
        }
        return new DiscoverVersionsResult(versions);
    }

    /** Parse a DeriveKey response payload. */
    public static DeriveKeyResult parseDeriveKeyPayload(Ttlv.Item payload) {
        if (payload == null) return new DeriveKeyResult(null);
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        return new DeriveKeyResult(uid != null ? uid.stringValue() : null);
    }

    /** Parse a CreateKeyPair response payload. */
    public static CreateKeyPairResult parseCreateKeyPairPayload(Ttlv.Item payload) {
        if (payload == null) return new CreateKeyPairResult(null, null);
        Ttlv.Item privUid = findChild(payload, Tag.PRIVATE_KEY_UNIQUE_IDENTIFIER);
        Ttlv.Item pubUid = findChild(payload, Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER);
        return new CreateKeyPairResult(
            privUid != null ? privUid.stringValue() : null,
            pubUid != null ? pubUid.stringValue() : null
        );
    }
}
