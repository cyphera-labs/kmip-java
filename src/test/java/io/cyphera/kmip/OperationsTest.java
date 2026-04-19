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

    // ---- buildActivateRequest ----

    @Test
    void buildActivateRequestHasActivateOperation() {
        byte[] request = Operations.buildActivateRequest("uid-1");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_ACTIVATE, operation.intValue());
    }

    @Test
    void buildActivateRequestContainsUid() {
        byte[] request = Operations.buildActivateRequest("uid-activate");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        assertEquals("uid-activate", uid.stringValue());
    }

    // ---- buildDestroyRequest ----

    @Test
    void buildDestroyRequestHasDestroyOperation() {
        byte[] request = Operations.buildDestroyRequest("uid-2");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_DESTROY, operation.intValue());
    }

    // ---- buildCheckRequest ----

    @Test
    void buildCheckRequestHasCheckOperation() {
        byte[] request = Operations.buildCheckRequest("uid-3");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_CHECK, operation.intValue());
    }

    // ---- buildCreateKeyPairRequest ----

    @Test
    void buildCreateKeyPairRequestHasCorrectOperation() {
        byte[] request = Operations.buildCreateKeyPairRequest("kp-1", Tag.ALG_RSA, 2048);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_CREATE_KEY_PAIR, operation.intValue());
    }

    @Test
    void buildCreateKeyPairRequestHasSignVerifyUsage() {
        byte[] request = Operations.buildCreateKeyPairRequest("kp-1", Tag.ALG_RSA, 2048);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item template = findChild(payload, Tag.TEMPLATE_ATTRIBUTE);
        Ttlv.Item usageAttr = template.children().get(2);
        Ttlv.Item usageValue = findChild(usageAttr, Tag.ATTRIBUTE_VALUE);
        assertEquals(Tag.USAGE_SIGN | Tag.USAGE_VERIFY, usageValue.intValue());
    }

    // ---- buildRegisterRequest ----

    @Test
    void buildRegisterRequestHasRegisterOperation() {
        byte[] material = {0x01, 0x02, 0x03, 0x04};
        byte[] request = Operations.buildRegisterRequest(Tag.OBJ_SYMMETRIC_KEY, material, "reg-key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_REGISTER, operation.intValue());
    }

    @Test
    void buildRegisterRequestContainsKeyMaterial() {
        byte[] material = {0x01, 0x02, 0x03, 0x04};
        byte[] request = Operations.buildRegisterRequest(Tag.OBJ_SYMMETRIC_KEY, material, "reg-key", Tag.ALG_AES, 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item symKey = findChild(payload, Tag.SYMMETRIC_KEY);
        assertNotNull(symKey);
        Ttlv.Item keyBlock = findChild(symKey, Tag.KEY_BLOCK);
        assertNotNull(keyBlock);
        Ttlv.Item keyValue = findChild(keyBlock, Tag.KEY_VALUE);
        assertNotNull(keyValue);
        Ttlv.Item km = findChild(keyValue, Tag.KEY_MATERIAL);
        assertArrayEquals(material, km.bytesValue());
    }

    @Test
    void buildRegisterRequestWithoutNameOmitsTemplate() {
        byte[] material = {0x01, 0x02};
        byte[] request = Operations.buildRegisterRequest(Tag.OBJ_SYMMETRIC_KEY, material, "", Tag.ALG_AES, 128);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item template = findChild(payload, Tag.TEMPLATE_ATTRIBUTE);
        assertNull(template);
    }

    // ---- buildReKeyRequest ----

    @Test
    void buildReKeyRequestHasReKeyOperation() {
        byte[] request = Operations.buildReKeyRequest("uid-rk");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_RE_KEY, operation.intValue());
    }

    // ---- buildDeriveKeyRequest ----

    @Test
    void buildDeriveKeyRequestHasDeriveKeyOperation() {
        byte[] request = Operations.buildDeriveKeyRequest("uid-dk", new byte[]{0x01}, "derived", 128);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_DERIVE_KEY, operation.intValue());
    }

    @Test
    void buildDeriveKeyRequestContainsDerivationData() {
        byte[] derivData = {0x0A, 0x0B};
        byte[] request = Operations.buildDeriveKeyRequest("uid-dk", derivData, "derived", 256);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item derivParams = findChild(payload, Tag.DERIVATION_PARAMETERS);
        assertNotNull(derivParams);
        Ttlv.Item dd = findChild(derivParams, Tag.DERIVATION_DATA);
        assertArrayEquals(derivData, dd.bytesValue());
    }

    // ---- buildGetAttributesRequest ----

    @Test
    void buildGetAttributesRequestHasCorrectOperation() {
        byte[] request = Operations.buildGetAttributesRequest("uid-ga");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_GET_ATTRIBUTES, operation.intValue());
    }

    // ---- buildGetAttributeListRequest ----

    @Test
    void buildGetAttributeListRequestHasCorrectOperation() {
        byte[] request = Operations.buildGetAttributeListRequest("uid-gal");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_GET_ATTRIBUTE_LIST, operation.intValue());
    }

    // ---- buildAddAttributeRequest ----

    @Test
    void buildAddAttributeRequestHasCorrectOperation() {
        byte[] request = Operations.buildAddAttributeRequest("uid-aa", "Comment", "test");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_ADD_ATTRIBUTE, operation.intValue());
    }

    @Test
    void buildAddAttributeRequestContainsAttribute() {
        byte[] request = Operations.buildAddAttributeRequest("uid-aa", "Comment", "my-comment");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item attr = findChild(payload, Tag.ATTRIBUTE);
        Ttlv.Item attrName = findChild(attr, Tag.ATTRIBUTE_NAME);
        assertEquals("Comment", attrName.stringValue());
        Ttlv.Item attrValue = findChild(attr, Tag.ATTRIBUTE_VALUE);
        assertEquals("my-comment", attrValue.stringValue());
    }

    // ---- buildModifyAttributeRequest ----

    @Test
    void buildModifyAttributeRequestHasCorrectOperation() {
        byte[] request = Operations.buildModifyAttributeRequest("uid-ma", "Comment", "updated");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_MODIFY_ATTRIBUTE, operation.intValue());
    }

    // ---- buildDeleteAttributeRequest ----

    @Test
    void buildDeleteAttributeRequestHasCorrectOperation() {
        byte[] request = Operations.buildDeleteAttributeRequest("uid-da", "Comment");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_DELETE_ATTRIBUTE, operation.intValue());
    }

    @Test
    void buildDeleteAttributeRequestContainsAttrName() {
        byte[] request = Operations.buildDeleteAttributeRequest("uid-da", "Comment");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item attr = findChild(payload, Tag.ATTRIBUTE);
        Ttlv.Item attrName = findChild(attr, Tag.ATTRIBUTE_NAME);
        assertEquals("Comment", attrName.stringValue());
    }

    // ---- buildObtainLeaseRequest ----

    @Test
    void buildObtainLeaseRequestHasCorrectOperation() {
        byte[] request = Operations.buildObtainLeaseRequest("uid-ol");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_OBTAIN_LEASE, operation.intValue());
    }

    // ---- buildRevokeRequest ----

    @Test
    void buildRevokeRequestHasRevokeOperation() {
        byte[] request = Operations.buildRevokeRequest("uid-rev", 1);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_REVOKE, operation.intValue());
    }

    @Test
    void buildRevokeRequestContainsRevocationReason() {
        byte[] request = Operations.buildRevokeRequest("uid-rev", 5);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item revReason = findChild(payload, Tag.REVOCATION_REASON);
        assertNotNull(revReason);
        Ttlv.Item reasonCode = findChild(revReason, Tag.REVOCATION_REASON_CODE);
        assertEquals(5, reasonCode.intValue());
    }

    // ---- buildArchiveRequest ----

    @Test
    void buildArchiveRequestHasArchiveOperation() {
        byte[] request = Operations.buildArchiveRequest("uid-arc");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_ARCHIVE, operation.intValue());
    }

    // ---- buildRecoverRequest ----

    @Test
    void buildRecoverRequestHasRecoverOperation() {
        byte[] request = Operations.buildRecoverRequest("uid-rec");
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_RECOVER, operation.intValue());
    }

    // ---- buildQueryRequest ----

    @Test
    void buildQueryRequestHasQueryOperation() {
        byte[] request = Operations.buildQueryRequest();
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_QUERY, operation.intValue());
    }

    @Test
    void buildQueryRequestHasEmptyPayload() {
        byte[] request = Operations.buildQueryRequest();
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        assertNotNull(payload);
        assertEquals(0, payload.children().size());
    }

    // ---- buildPollRequest ----

    @Test
    void buildPollRequestHasPollOperation() {
        byte[] request = Operations.buildPollRequest();
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_POLL, operation.intValue());
    }

    // ---- buildDiscoverVersionsRequest ----

    @Test
    void buildDiscoverVersionsRequestHasCorrectOperation() {
        byte[] request = Operations.buildDiscoverVersionsRequest();
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_DISCOVER_VERSIONS, operation.intValue());
    }

    // ---- buildEncryptRequest ----

    @Test
    void buildEncryptRequestHasEncryptOperation() {
        byte[] request = Operations.buildEncryptRequest("uid-enc", new byte[]{0x01, 0x02});
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_ENCRYPT, operation.intValue());
    }

    @Test
    void buildEncryptRequestContainsData() {
        byte[] data = {0x0A, 0x0B, 0x0C};
        byte[] request = Operations.buildEncryptRequest("uid-enc", data);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item dataItem = findChild(payload, Tag.DATA);
        assertArrayEquals(data, dataItem.bytesValue());
    }

    // ---- buildDecryptRequest ----

    @Test
    void buildDecryptRequestHasDecryptOperation() {
        byte[] request = Operations.buildDecryptRequest("uid-dec", new byte[]{0x01}, null);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_DECRYPT, operation.intValue());
    }

    @Test
    void buildDecryptRequestWithNonceIncludesIV() {
        byte[] nonce = {0x01, 0x02, 0x03};
        byte[] request = Operations.buildDecryptRequest("uid-dec", new byte[]{0x0A}, nonce);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item iv = findChild(payload, Tag.IV_COUNTER_NONCE);
        assertNotNull(iv);
        assertArrayEquals(nonce, iv.bytesValue());
    }

    @Test
    void buildDecryptRequestWithoutNonceOmitsIV() {
        byte[] request = Operations.buildDecryptRequest("uid-dec", new byte[]{0x0A}, null);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item iv = findChild(payload, Tag.IV_COUNTER_NONCE);
        assertNull(iv);
    }

    // ---- buildSignRequest ----

    @Test
    void buildSignRequestHasSignOperation() {
        byte[] request = Operations.buildSignRequest("uid-sign", new byte[]{0x01});
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_SIGN, operation.intValue());
    }

    // ---- buildSignatureVerifyRequest ----

    @Test
    void buildSignatureVerifyRequestHasCorrectOperation() {
        byte[] request = Operations.buildSignatureVerifyRequest("uid-sv", new byte[]{0x01}, new byte[]{0x02});
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_SIGNATURE_VERIFY, operation.intValue());
    }

    @Test
    void buildSignatureVerifyRequestContainsSignatureData() {
        byte[] sig = {0x0A, 0x0B};
        byte[] request = Operations.buildSignatureVerifyRequest("uid-sv", new byte[]{0x01}, sig);
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item sigData = findChild(payload, Tag.SIGNATURE_DATA);
        assertArrayEquals(sig, sigData.bytesValue());
    }

    // ---- buildMacRequest ----

    @Test
    void buildMacRequestHasMacOperation() {
        byte[] request = Operations.buildMacRequest("uid-mac", new byte[]{0x01});
        Ttlv.Item decoded = decodeTTLV(request);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item operation = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_MAC, operation.intValue());
    }

    // ---- parseCheckPayload ----

    @Test
    void parseCheckPayloadExtractsUid() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "check-id")
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.CheckResult result = Operations.parseCheckPayload(decoded);
        assertEquals("check-id", result.uniqueIdentifier);
    }

    @Test
    void parseCheckPayloadHandlesNull() {
        Operations.CheckResult result = Operations.parseCheckPayload(null);
        assertNull(result.uniqueIdentifier);
    }

    // ---- parseReKeyPayload ----

    @Test
    void parseReKeyPayloadExtractsUid() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "rekey-id")
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.ReKeyResult result = Operations.parseReKeyPayload(decoded);
        assertEquals("rekey-id", result.uniqueIdentifier);
    }

    // ---- parseEncryptPayload ----

    @Test
    void parseEncryptPayloadExtractsDataAndNonce() {
        byte[] encData = {0x0A, 0x0B, 0x0C};
        byte[] encNonce = {0x01, 0x02};
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeByteString(Tag.DATA, encData),
            encodeByteString(Tag.IV_COUNTER_NONCE, encNonce)
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.EncryptResult result = Operations.parseEncryptPayload(decoded);
        assertArrayEquals(encData, result.data);
        assertArrayEquals(encNonce, result.nonce);
    }

    @Test
    void parseEncryptPayloadHandlesNull() {
        Operations.EncryptResult result = Operations.parseEncryptPayload(null);
        assertNull(result.data);
        assertNull(result.nonce);
    }

    // ---- parseDecryptPayload ----

    @Test
    void parseDecryptPayloadExtractsData() {
        byte[] plaintext = {0x01, 0x02, 0x03};
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeByteString(Tag.DATA, plaintext)
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.DecryptResult result = Operations.parseDecryptPayload(decoded);
        assertArrayEquals(plaintext, result.data);
    }

    // ---- parseSignPayload ----

    @Test
    void parseSignPayloadExtractsSignatureData() {
        byte[] sig = {0x0A, 0x0B, 0x0C, 0x0D};
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeByteString(Tag.SIGNATURE_DATA, sig)
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.SignResult result = Operations.parseSignPayload(decoded);
        assertArrayEquals(sig, result.signatureData);
    }

    // ---- parseSignatureVerifyPayload ----

    @Test
    void parseSignatureVerifyPayloadValidWhenIndicatorZero() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeEnum(Tag.VALIDITY_INDICATOR, 0)
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.SignatureVerifyResult result = Operations.parseSignatureVerifyPayload(decoded);
        assertTrue(result.valid);
    }

    @Test
    void parseSignatureVerifyPayloadInvalidWhenIndicatorNonZero() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeEnum(Tag.VALIDITY_INDICATOR, 1)
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.SignatureVerifyResult result = Operations.parseSignatureVerifyPayload(decoded);
        assertFalse(result.valid);
    }

    // ---- parseMacPayload ----

    @Test
    void parseMacPayloadExtractsMacData() {
        byte[] macBytes = {0x01, 0x02, 0x03};
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeByteString(Tag.MAC_DATA, macBytes)
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.MACResult result = Operations.parseMacPayload(decoded);
        assertArrayEquals(macBytes, result.macData);
    }

    // ---- parseQueryPayload ----

    @Test
    void parseQueryPayloadExtractsOperationsAndObjectTypes() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeEnum(Tag.OPERATION, Tag.OP_CREATE),
            encodeEnum(Tag.OPERATION, Tag.OP_GET),
            encodeEnum(Tag.OBJECT_TYPE, Tag.OBJ_SYMMETRIC_KEY)
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.QueryResult result = Operations.parseQueryPayload(decoded);
        assertEquals(2, result.operations.size());
        assertEquals(Tag.OP_CREATE, result.operations.get(0).intValue());
        assertEquals(Tag.OP_GET, result.operations.get(1).intValue());
        assertEquals(1, result.objectTypes.size());
        assertEquals(Tag.OBJ_SYMMETRIC_KEY, result.objectTypes.get(0).intValue());
    }

    @Test
    void parseQueryPayloadHandlesNull() {
        Operations.QueryResult result = Operations.parseQueryPayload(null);
        assertTrue(result.operations.isEmpty());
        assertTrue(result.objectTypes.isEmpty());
    }

    // ---- parseDiscoverVersionsPayload ----

    @Test
    void parseDiscoverVersionsPayloadExtractsVersions() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeStructure(Tag.PROTOCOL_VERSION,
                encodeInteger(Tag.PROTOCOL_VERSION_MAJOR, 1),
                encodeInteger(Tag.PROTOCOL_VERSION_MINOR, 4)
            ),
            encodeStructure(Tag.PROTOCOL_VERSION,
                encodeInteger(Tag.PROTOCOL_VERSION_MAJOR, 1),
                encodeInteger(Tag.PROTOCOL_VERSION_MINOR, 2)
            )
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.DiscoverVersionsResult result = Operations.parseDiscoverVersionsPayload(decoded);
        assertEquals(2, result.versions.size());
        assertEquals(1, result.versions.get(0)[0]);
        assertEquals(4, result.versions.get(0)[1]);
        assertEquals(1, result.versions.get(1)[0]);
        assertEquals(2, result.versions.get(1)[1]);
    }

    // ---- parseDeriveKeyPayload ----

    @Test
    void parseDeriveKeyPayloadExtractsUid() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeTextString(Tag.UNIQUE_IDENTIFIER, "derived-id")
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.DeriveKeyResult result = Operations.parseDeriveKeyPayload(decoded);
        assertEquals("derived-id", result.uniqueIdentifier);
    }

    // ---- parseCreateKeyPairPayload ----

    @Test
    void parseCreateKeyPairPayloadExtractsBothUids() {
        byte[] payload = encodeStructure(Tag.RESPONSE_PAYLOAD,
            encodeTextString(Tag.PRIVATE_KEY_UNIQUE_IDENTIFIER, "priv-id"),
            encodeTextString(Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER, "pub-id")
        );
        Ttlv.Item decoded = decodeTTLV(payload);
        Operations.CreateKeyPairResult result = Operations.parseCreateKeyPairPayload(decoded);
        assertEquals("priv-id", result.privateKeyUid);
        assertEquals("pub-id", result.publicKeyUid);
    }

    @Test
    void parseCreateKeyPairPayloadHandlesNull() {
        Operations.CreateKeyPairResult result = Operations.parseCreateKeyPairPayload(null);
        assertNull(result.privateKeyUid);
        assertNull(result.publicKeyUid);
    }

    // ---- Round-trip: build -> encode -> decode -> verify ----

    @Test
    void roundTripLocateRequest() {
        byte[] encoded = Operations.buildLocateRequest("round-trip-key");
        Ttlv.Item decoded = decodeTTLV(encoded);
        assertEquals(Tag.REQUEST_MESSAGE, decoded.tag);
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

    @Test
    void roundTripEncryptRequest() {
        byte[] data = {0x01, 0x02, 0x03, 0x04};
        byte[] encoded = Operations.buildEncryptRequest("rt-enc", data);
        Ttlv.Item decoded = decodeTTLV(encoded);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        assertEquals("rt-enc", uid.stringValue());
        Ttlv.Item dataItem = findChild(payload, Tag.DATA);
        assertArrayEquals(data, dataItem.bytesValue());
    }

    @Test
    void roundTripRevokeRequest() {
        byte[] encoded = Operations.buildRevokeRequest("rt-rev", 3);
        Ttlv.Item decoded = decodeTTLV(encoded);
        Ttlv.Item batchItem = findChild(decoded, Tag.BATCH_ITEM);
        Ttlv.Item op = findChild(batchItem, Tag.OPERATION);
        assertEquals(Tag.OP_REVOKE, op.intValue());
        Ttlv.Item payload = findChild(batchItem, Tag.REQUEST_PAYLOAD);
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        assertEquals("rt-rev", uid.stringValue());
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
