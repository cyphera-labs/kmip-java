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
 * KMIP request/response builders for Locate, Get, and Create operations.
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

    // --- Request builders ---

    /** Build the request header (included in every request). */
    static byte[] buildRequestHeader(int batchCount) {
        return encodeStructure(Tag.REQUEST_HEADER,
            encodeStructure(Tag.PROTOCOL_VERSION,
                encodeInteger(Tag.PROTOCOL_VERSION_MAJOR, PROTOCOL_MAJOR),
                encodeInteger(Tag.PROTOCOL_VERSION_MINOR, PROTOCOL_MINOR)
            ),
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
        int resultStatus = statusItem != null ? statusItem.intValue() : 0;
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
        List<Ttlv.Item> ids = findChildren(payload, Tag.UNIQUE_IDENTIFIER);
        List<String> result = new ArrayList<>();
        for (Ttlv.Item id : ids) {
            result.add(id.stringValue());
        }
        return new LocateResult(result);
    }

    /** Parse a Get response payload. */
    public static GetResult parseGetPayload(Ttlv.Item payload) {
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
        Ttlv.Item uid = findChild(payload, Tag.UNIQUE_IDENTIFIER);
        Ttlv.Item objType = findChild(payload, Tag.OBJECT_TYPE);
        return new CreateResult(
            objType != null ? objType.intValue() : 0,
            uid != null ? uid.stringValue() : null
        );
    }
}
