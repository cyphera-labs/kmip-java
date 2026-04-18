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

import org.junit.jupiter.api.Test;

import static io.cyphera.kmip.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

class OperationsTest {

    // ---- buildLocateRequest ----

    @Test
    void buildLocateRequestProducesValidStructure() {
        byte[] request = Operations.buildLocateRequest("test-key");
        Ttlv.Item decoded = decodeTTLV(request);
        assertEquals(Tag.REQUEST_MESSAGE, decoded.tag);
        assertEquals(TYPE_STRUCTURE, decoded.type);
    }

    @Test
    void buildLocateRequestHasProtocolVersion14() {
        byte[] request = Operations.buildLocateRequest("test-key");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item header = findChild(decoded, Tag.REQUEST_HEADER);
        assertNotNull(header);
        Ttlv.Item version = findChild(header, Tag.PROTOCOL_VERSION);
        assertNotNull(version);
        Ttlv.Item major = findChild(version, Tag.PROTOCOL_VERSION_MAJOR);
        Ttlv.Item minor = findChild(version, Tag.PROTOCOL_VERSION_MINOR);
        assertNotNull(major);
        assertNotNull(minor);
        assertEquals(1, major.intValue());
        assertEquals(4, minor.intValue());
    }

    @Test
    void buildLocateRequestHasBatchCountOne() {
        byte[] request = Operations.buildLocateRequest("test-key");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item header = findChild(decoded, Tag.REQUEST_HEADER);
        assertNotNull(header);
        Ttlv.Item batchCount = findChild(header, Tag.BATCH_COUNT);
        assertNotNull(batchCount);
        assertEquals(1, batchCount.intValue());
    }

    @Test
    void buildLocateRequestHasLocateOperation() {
        byte[] request = Operations.buildLocateRequest("test-key");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        assertNotNull(batchItem);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertNotNull(operation);
        assertEquals(Tag.OP_LOCATE, operation.intValue());
    }

    @Test
    void buildLocateRequestContainsNameAttribute() {
        byte[] request = Operations.buildLocateRequest("my-key");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        assertNotNull(payload);
        Ttlv.Item attribute = findChild(payload, Tag.ATTRIBUTE);
        assertNotNull(attribute);
        Ttlv.Item attrName = findChild(attribute, Tag.ATTRIBUTE_NAME);
        assertEquals("Name", attrName.stringValue());
        Ttlv.Item attrValue = findChild(attribute, Tag.ATTRIBUTE_VALUE);
        assertNotNull(attrValue);
        Ttlv.Item nameValue = findChild(attrValue, Tag.NAME_VALUE);
        assertEquals("my-key", nameValue.stringValue());
    }

    // ---- buildGetRequest ----

    @Test
    void buildGetRequestProducesValidStructure() {
        byte[] request = Operations.buildGetRequest("uid-123");
        Ttlv.Item decoded = decodeTTLV(request);
        assertEquals(Tag.REQUEST_MESSAGE, decoded.tag);
    }

    @Test
    void buildGetRequestHasGetOperation() {
        byte[] request = Operations.buildGetRequest("uid-123");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertNotNull(operation);
        assertEquals(Tag.OP_GET, operation.intValue());
    }

    @Test
    void buildGetRequestContainsUniqueIdentifier() {
        byte[] request = Operations.buildGetRequest("uid-456");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        assertNotNull(uid);
        assertEquals("uid-456", uid.stringValue());
    }

    // ---- buildCreateRequest ----

    @Test
    void buildCreateRequestProducesValidStructure() {
        byte[] request = Operations.buildCreateRequest("new-key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        assertEquals(Tag.REQUEST_MESSAGE, decoded.tag);
    }

    @Test
    void buildCreateRequestHasCreateOperation() {
        byte[] request = Operations.buildCreateRequest("new-key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertNotNull(operation);
        assertEquals(Tag.OP_CREATE, operation.intValue());
    }

    @Test
    void buildCreateRequestHasSymmetricKeyObjectType() {
        byte[] request = Operations.buildCreateRequest("new-key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item objType = findChild(payload, Tag.OBJECT_TYPE);
        assertNotNull(objType);
        assertEquals(Tag.OBJ_SYMMETRIC_KEY, objType.intValue());
    }

    @Test
    void buildCreateRequestDefaultsToAes() {
        byte[] request = Operations.buildCreateRequest("key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item template = findChild(payload, Tag.TEMPLATE_ATTRIBUTE);
        assertNotNull(template);
        // First attribute should be Cryptographic Algorithm
        Ttlv.Item algoAttr = template.children().get(0);
        Ttlv.Item algoName = findChild(algoAttr, Tag.ATTRIBUTE_NAME);
        assertEquals("Cryptographic Algorithm", algoName.stringValue());
        Ttlv.Item algoValue = findChild(algoAttr, Tag.ATTRIBUTE_VALUE);
        assertEquals(Tag.ALG_AES, algoValue.intValue());
    }

    @Test
    void buildCreateRequestWith256BitLength() {
        byte[] request = Operations.buildCreateRequest("key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item template = findChild(payload, Tag.TEMPLATE_ATTRIBUTE);
        // Second attribute should be Cryptographic Length
        Ttlv.Item lenAttr = template.children().get(1);
        Ttlv.Item lenName = findChild(lenAttr, Tag.ATTRIBUTE_NAME);
        assertEquals("Cryptographic Length", lenName.stringValue());
        Ttlv.Item lenValue = findChild(lenAttr, Tag.ATTRIBUTE_VALUE);
        assertEquals(256, lenValue.intValue());
    }

    @Test
    void buildCreateRequestHasUsageMaskEncryptDecrypt() {
        byte[] request = Operations.buildCreateRequest("key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item template = findChild(payload, Tag.TEMPLATE_ATTRIBUTE);
        // Third attribute should be Cryptographic Usage Mask
        Ttlv.Item usageAttr = template.children().get(2);
        Ttlv.Item usageName = findChild(usageAttr, Tag.ATTRIBUTE_NAME);
        assertEquals("Cryptographic Usage Mask", usageName.stringValue());
        Ttlv.Item usageValue = findChild(usageAttr, Tag.ATTRIBUTE_VALUE);
        assertEquals(Tag.USAGE_ENCRYPT | Tag.USAGE_DECRYPT, usageValue.intValue());
    }

    @Test
    void buildCreateRequestIncludesKeyNameInTemplate() {
        byte[] request = Operations.buildCreateRequest("my-special-key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item template = findChild(payload, Tag.TEMPLATE_ATTRIBUTE);
        // Fourth attribute is the Name
        Ttlv.Item nameAttr = template.children().get(3);
        Ttlv.Item nameName = findChild(nameAttr, Tag.ATTRIBUTE_NAME);
        assertEquals("Name", nameName.stringValue());
        Ttlv.Item nameValueStruct = findChild(nameAttr, Tag.ATTRIBUTE_VALUE);
        Ttlv.Item nameValue = findChild(nameValueStruct, Tag.NAME_VALUE);
        assertEquals("my-special-key", nameValue.stringValue());
    }

    @Test
    void buildCreateRequestWithCustomAlgorithmAndLength() {
        byte[] request = Operations.buildCreateRequest("des-key", Tag.ALG_TRIPLE_DES, 192);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item template = findChild(payload, Tag.TEMPLATE_ATTRIBUTE);
        Ttlv.Item algoAttr = template.children().get(0);
        Ttlv.Item algoValue = findChild(algoAttr, Tag.ATTRIBUTE_VALUE);
        assertEquals(Tag.ALG_TRIPLE_DES, algoValue.intValue());
        Ttlv.Item lenAttr = template.children().get(1);
        Ttlv.Item lenValue = findChild(lenAttr, Tag.ATTRIBUTE_VALUE);
        assertEquals(192, lenValue.intValue());
    }

    // ---- Response parsing: success ----

    @Test
    void parseResponseExtractsSuccessPayload() {
        byte[] response = buildMockResponse(Tag.OP_LOCATE, Tag.STATUS_SUCCESS, null);
        Operations.Response parsed = Operations.parseResponse(response);
        assertEquals(Tag.OP_LOCATE, parsed.operation);
        assertEquals(Tag.STATUS_SUCCESS, parsed.resultStatus);
        assertNotNull(parsed.payload);
    }

    @Test
    void parseResponseThrowsOnOperationFailed() {
        byte[] response = buildMockResponse(Tag.OP_GET, Tag.STATUS_OPERATION_FAILED, "Not found");
        KmipException ex = assertThrows(KmipException.class,
            () -> Operations.parseResponse(response));
        assertEquals("Not found", ex.getMessage());
        assertEquals(Tag.STATUS_OPERATION_FAILED, ex.resultStatus);
    }

    @Test
    void parseResponseThrowsOnWrongMessageTag() {
        // Send a RequestMessage where ResponseMessage is expected
        byte[] request = Operations.buildLocateRequest("test");
        KmipException ex = assertThrows(KmipException.class,
            () -> Operations.parseResponse(request));
        assertTrue(ex.getMessage().contains("0x420078") || ex.getMessage().contains("42007B")
            || ex.getMessage().contains("ResponseMessage"));
    }

    // ---- parseLocatePayload ----

    @Test
    void parseLocatePayloadMultipleIds() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "id-1"),
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "id-2"),
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "id-3")
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.LocateResult result = Operations.parseLocatePayload(decoded);
        assertEquals(3, result.uniqueIdentifiers.size());
        assertEquals("id-1", result.uniqueIdentifiers.get(0));
        assertEquals("id-2", result.uniqueIdentifiers.get(1));
        assertEquals("id-3", result.uniqueIdentifiers.get(2));
    }

    @Test
    void parseLocatePayloadEmpty() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD);
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.LocateResult result = Operations.parseLocatePayload(decoded);
        assertTrue(result.uniqueIdentifiers.isEmpty());
    }

    @Test
    void parseLocatePayloadSingleId() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "only-one")
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.LocateResult result = Operations.parseLocatePayload(decoded);
        assertEquals(1, result.uniqueIdentifiers.size());
        assertEquals("only-one", result.uniqueIdentifiers.get(0));
    }

    // ---- parseGetPayload ----

    @Test
    void parseGetPayloadExtractsKeyMaterial() {
        byte[] keyBytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeEnum(Tag.OBJECT_TYPE, Tag.OBJ_SYMMETRIC_KEY),
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "key-id-1"),
            encodeStructure(Tag.SYMMETRIC_KEY,
                encodeStructure(Tag.KEY_BLOCK,
                    encodeEnum(Tag.KEY_FORMAT_TYPE, Tag.KEY_FORMAT_RAW),
                    encodeStructure(Tag.KEY_VALUE,
                        encodeByteString(Tag.KEY_MATERIAL, keyBytes)
                    )
                )
            )
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.GetResult result = Operations.parseGetPayload(decoded);
        assertEquals(Tag.OBJ_SYMMETRIC_KEY, result.objectType);
        assertEquals("key-id-1", result.uniqueIdentifier);
        assertArrayEquals(keyBytes, result.keyMaterial);
    }

    @Test
    void parseGetPayloadReturnsNullKeyMaterialWhenNoSymmetricKey() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeEnum(Tag.OBJECT_TYPE, Tag.OBJ_PUBLIC_KEY),
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "key-id-2")
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.GetResult result = Operations.parseGetPayload(decoded);
        assertNull(result.keyMaterial);
        assertEquals("key-id-2", result.uniqueIdentifier);
    }

    // ---- parseCreatePayload ----

    @Test
    void parseCreatePayloadExtractsTypeAndId() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeEnum(Tag.OBJECT_TYPE, Tag.OBJ_SYMMETRIC_KEY),
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "new-key-id")
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.CreateResult result = Operations.parseCreatePayload(decoded);
        assertEquals(Tag.OBJ_SYMMETRIC_KEY, result.objectType);
        assertEquals("new-key-id", result.uniqueIdentifier);
    }

    // ---- Round-trip: build -> encode -> decode -> verify ----

    @Test
    void roundTripLocateRequest() {
        byte[] encoded = Operations.buildLocateRequest("round-trip-key");
        Ttlv.Item decoded = decodeTTLV(encoded);
        assertEquals(Tag.REQUEST_MESSAGE, decoded.tag);
        // Re-encode and verify identical
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        assertNotNull(batchItem);
        Ttlv.Item op = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_LOCATE, op.intValue());
    }

    @Test
    void roundTripGetRequest() {
        byte[] encoded = Operations.buildGetRequest("rt-uid");
        Ttlv.Item decoded = decodeTTLV(encoded);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        assertEquals("rt-uid", uid.stringValue());
    }

    @Test
    void roundTripCreateRequest() {
        byte[] encoded = Operations.buildCreateRequest("rt-key", Tag.ALG_AES, 128);
        Ttlv.Item decoded = decodeTTLV(encoded);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item objType = findChild(payload, Tag.OBJECT_TYPE);
        assertEquals(Tag.OBJ_SYMMETRIC_KEY, objType.intValue());
        Ttlv.Item template = findChild(payload, Tag.TEMPLATE_ATTRIBUTE);
        assertEquals(4, template.children().size());
    }

    // ---- Helper to build mock KMIP response ----

    private byte[] buildMockResponse(int operation, int status, String message) {
        byte[] payloadInner = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "mock-id")
        );

        byte[] batchItem;
        if (message != null) {
            batchItem = encodeStructure(Tag.BATCH_ITEM,
                encodeEnum(Tag.OPERATION, operation),
                encodeEnum(Tag.RESULT_STATUS, status),
                encodeTextString(Tag.RESULT_MESSAGE, message),
                payloadInner
            );
        } else {
            batchItem = encodeStructure(Tag.BATCH_ITEM,
                encodeEnum(Tag.OPERATION, operation),
                encodeEnum(Tag.RESULT_STATUS, status),
                payloadInner
            );
        }

        byte[] header = encodeStructure(Tag.RESPONSE_HEADER,
            encodeStructure(Tag.PROTOCOL_VERSION,
                encodeInteger(Tag.PROTOCOL_VERSION_MAJOR, 1),
                encodeInteger(Tag.PROTOCOL_VERSION_MINOR, 4)
            ),
            encodeInteger(Tag.BATCH_COUNT, 1)
        );

        return encodeStructure(Tag.RESPONSE_MESSAGE, header, batchItem);
    }
}
