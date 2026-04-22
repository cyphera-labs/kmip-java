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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class TagTest {

    // ---- ObjectType values per KMIP 1.4 ----

    @Test
    void objectTypeCertificateIsOne() {
        assertEquals(1, Tag.OBJ_CERTIFICATE);
    }

    @Test
    void objectTypeSymmetricKeyIsTwo() {
        assertEquals(2, Tag.OBJ_SYMMETRIC_KEY);
    }

    @Test
    void objectTypePublicKeyIsThree() {
        assertEquals(3, Tag.OBJ_PUBLIC_KEY);
    }

    @Test
    void objectTypePrivateKeyIsFour() {
        assertEquals(4, Tag.OBJ_PRIVATE_KEY);
    }

    @Test
    void objectTypeSplitKeyIsFive() {
        assertEquals(5, Tag.OBJ_SPLIT_KEY);
    }

    @Test
    void objectTypeTemplateIsSix() {
        assertEquals(6, Tag.OBJ_TEMPLATE);
    }

    @Test
    void objectTypeSecretDataIsSeven() {
        assertEquals(7, Tag.OBJ_SECRET_DATA);
    }

    @Test
    void objectTypeOpaqueDataIsEight() {
        assertEquals(8, Tag.OBJ_OPAQUE_DATA);
    }

    @Test
    void objectTypeValuesAreUnique() {
        int[] values = {
            Tag.OBJ_CERTIFICATE, Tag.OBJ_SYMMETRIC_KEY, Tag.OBJ_PUBLIC_KEY,
            Tag.OBJ_PRIVATE_KEY, Tag.OBJ_SPLIT_KEY, Tag.OBJ_TEMPLATE,
            Tag.OBJ_SECRET_DATA, Tag.OBJ_OPAQUE_DATA
        };
        Set<Integer> set = new HashSet<>();
        for (int v : values) set.add(v);
        assertEquals(values.length, set.size(), "Object type values must be unique");
    }

    // ---- Operation values ----

    @Test
    void operationCreateIsOne() {
        assertEquals(1, Tag.OP_CREATE);
    }

    @Test
    void operationLocateIsEight() {
        assertEquals(8, Tag.OP_LOCATE);
    }

    @Test
    void operationGetIs0xA() {
        assertEquals(0x0A, Tag.OP_GET);
    }

    @Test
    void operationActivateIs0x12() {
        assertEquals(0x12, Tag.OP_ACTIVATE);
    }

    @Test
    void operationDestroyIs0x14() {
        assertEquals(0x14, Tag.OP_DESTROY);
    }

    @Test
    void operationCheckIs0x09() {
        assertEquals(0x09, Tag.OP_CHECK);
    }

    @Test
    void operationCreateKeyPairIs0x02() {
        assertEquals(0x02, Tag.OP_CREATE_KEY_PAIR);
    }

    @Test
    void operationRegisterIs0x03() {
        assertEquals(0x03, Tag.OP_REGISTER);
    }

    @Test
    void operationReKeyIs0x04() {
        assertEquals(0x04, Tag.OP_RE_KEY);
    }

    @Test
    void operationDeriveKeyIs0x05() {
        assertEquals(0x05, Tag.OP_DERIVE_KEY);
    }

    @Test
    void operationGetAttributesIs0x0B() {
        assertEquals(0x0B, Tag.OP_GET_ATTRIBUTES);
    }

    @Test
    void operationGetAttributeListIs0x0C() {
        assertEquals(0x0C, Tag.OP_GET_ATTRIBUTE_LIST);
    }

    @Test
    void operationAddAttributeIs0x0D() {
        assertEquals(0x0D, Tag.OP_ADD_ATTRIBUTE);
    }

    @Test
    void operationModifyAttributeIs0x0E() {
        assertEquals(0x0E, Tag.OP_MODIFY_ATTRIBUTE);
    }

    @Test
    void operationDeleteAttributeIs0x0F() {
        assertEquals(0x0F, Tag.OP_DELETE_ATTRIBUTE);
    }

    @Test
    void operationObtainLeaseIs0x10() {
        assertEquals(0x10, Tag.OP_OBTAIN_LEASE);
    }

    @Test
    void operationRevokeIs0x13() {
        assertEquals(0x13, Tag.OP_REVOKE);
    }

    @Test
    void operationArchiveIs0x15() {
        assertEquals(0x15, Tag.OP_ARCHIVE);
    }

    @Test
    void operationRecoverIs0x16() {
        assertEquals(0x16, Tag.OP_RECOVER);
    }

    @Test
    void operationQueryIs0x18() {
        assertEquals(0x18, Tag.OP_QUERY);
    }

    @Test
    void operationPollIs0x1A() {
        assertEquals(0x1A, Tag.OP_POLL);
    }

    @Test
    void operationDiscoverVersionsIs0x1E() {
        assertEquals(0x1E, Tag.OP_DISCOVER_VERSIONS);
    }

    @Test
    void operationEncryptIs0x1F() {
        assertEquals(0x1F, Tag.OP_ENCRYPT);
    }

    @Test
    void operationDecryptIs0x20() {
        assertEquals(0x20, Tag.OP_DECRYPT);
    }

    @Test
    void operationSignIs0x21() {
        assertEquals(0x21, Tag.OP_SIGN);
    }

    @Test
    void operationSignatureVerifyIs0x22() {
        assertEquals(0x22, Tag.OP_SIGNATURE_VERIFY);
    }

    @Test
    void operationMacIs0x23() {
        assertEquals(0x23, Tag.OP_MAC);
    }

    @Test
    void all27OperationValuesAreUnique() {
        int[] values = {
            Tag.OP_CREATE, Tag.OP_CREATE_KEY_PAIR, Tag.OP_REGISTER, Tag.OP_RE_KEY,
            Tag.OP_DERIVE_KEY, Tag.OP_LOCATE, Tag.OP_CHECK, Tag.OP_GET,
            Tag.OP_GET_ATTRIBUTES, Tag.OP_GET_ATTRIBUTE_LIST,
            Tag.OP_ADD_ATTRIBUTE, Tag.OP_MODIFY_ATTRIBUTE, Tag.OP_DELETE_ATTRIBUTE,
            Tag.OP_OBTAIN_LEASE, Tag.OP_ACTIVATE, Tag.OP_REVOKE, Tag.OP_DESTROY,
            Tag.OP_ARCHIVE, Tag.OP_RECOVER, Tag.OP_QUERY, Tag.OP_POLL,
            Tag.OP_DISCOVER_VERSIONS, Tag.OP_ENCRYPT, Tag.OP_DECRYPT,
            Tag.OP_SIGN, Tag.OP_SIGNATURE_VERIFY, Tag.OP_MAC
        };
        Set<Integer> set = new HashSet<>();
        for (int v : values) set.add(v);
        assertEquals(27, values.length, "Should have exactly 27 operations");
        assertEquals(values.length, set.size(), "Operation values must be unique");
    }

    // ---- ResultStatus values ----

    @Test
    void resultStatusSuccessIsZero() {
        assertEquals(0, Tag.STATUS_SUCCESS);
    }

    @Test
    void resultStatusOperationFailedIsOne() {
        assertEquals(1, Tag.STATUS_OPERATION_FAILED);
    }

    @Test
    void resultStatusOperationPendingIsTwo() {
        assertEquals(2, Tag.STATUS_OPERATION_PENDING);
    }

    @Test
    void resultStatusOperationUndoneIsThree() {
        assertEquals(3, Tag.STATUS_OPERATION_UNDONE);
    }

    // ---- Algorithm values ----

    @Test
    void algorithmDesIsOne() {
        assertEquals(1, Tag.ALG_DES);
    }

    @Test
    void algorithmTripleDesIsTwo() {
        assertEquals(2, Tag.ALG_TRIPLE_DES);
    }

    @Test
    void algorithmAesIsThree() {
        assertEquals(3, Tag.ALG_AES);
    }

    @Test
    void algorithmRsaIsFour() {
        assertEquals(4, Tag.ALG_RSA);
    }

    @Test
    void algorithmDsaIsFive() {
        assertEquals(5, Tag.ALG_DSA);
    }

    @Test
    void algorithmEcdsaIsSix() {
        assertEquals(6, Tag.ALG_ECDSA);
    }

    @Test
    void algorithmHmacSha1IsSeven() {
        assertEquals(7, Tag.ALG_HMAC_SHA1);
    }

    @Test
    void algorithmHmacSha224Is0x08() {
        assertEquals(0x08, Tag.ALG_HMAC_SHA224);
    }

    @Test
    void algorithmHmacSha256Is0x09() {
        assertEquals(0x09, Tag.ALG_HMAC_SHA256);
    }

    @Test
    void algorithmHmacSha384Is0x0A() {
        assertEquals(0x0A, Tag.ALG_HMAC_SHA384);
    }

    @Test
    void algorithmHmacSha512Is0x0B() {
        assertEquals(0x0B, Tag.ALG_HMAC_SHA512);
    }

    @Test
    void algorithmHmacMd5Is0x0C() {
        assertEquals(0x0C, Tag.ALG_HMAC_MD5);
    }

    @Test
    void algorithmValuesAreUnique() {
        int[] values = {
            Tag.ALG_DES, Tag.ALG_TRIPLE_DES, Tag.ALG_AES, Tag.ALG_RSA,
            Tag.ALG_DSA, Tag.ALG_ECDSA, Tag.ALG_HMAC_SHA1, Tag.ALG_HMAC_SHA224,
            Tag.ALG_HMAC_SHA256, Tag.ALG_HMAC_SHA384, Tag.ALG_HMAC_SHA512, Tag.ALG_HMAC_MD5
        };
        Set<Integer> set = new HashSet<>();
        for (int v : values) set.add(v);
        assertEquals(values.length, set.size(), "Algorithm values must be unique");
    }

    // ---- KeyFormatType values ----

    @Test
    void keyFormatRawIsOne() {
        assertEquals(1, Tag.KEY_FORMAT_RAW);
    }

    @Test
    void keyFormatOpaqueIsTwo() {
        assertEquals(2, Tag.KEY_FORMAT_OPAQUE);
    }

    @Test
    void keyFormatPkcs1IsThree() {
        assertEquals(3, Tag.KEY_FORMAT_PKCS1);
    }

    @Test
    void keyFormatPkcs8IsFour() {
        assertEquals(4, Tag.KEY_FORMAT_PKCS8);
    }

    @Test
    void keyFormatX509IsFive() {
        assertEquals(5, Tag.KEY_FORMAT_X509);
    }

    @Test
    void keyFormatEcPrivateKeyIsSix() {
        assertEquals(6, Tag.KEY_FORMAT_EC_PRIVATE_KEY);
    }

    @Test
    void keyFormatTransparentSymmetricIsSeven() {
        assertEquals(7, Tag.KEY_FORMAT_TRANSPARENT_SYMMETRIC);
    }

    @Test
    void keyFormatTypeValuesAreUnique() {
        int[] values = {
            Tag.KEY_FORMAT_RAW, Tag.KEY_FORMAT_OPAQUE, Tag.KEY_FORMAT_PKCS1,
            Tag.KEY_FORMAT_PKCS8, Tag.KEY_FORMAT_X509, Tag.KEY_FORMAT_EC_PRIVATE_KEY,
            Tag.KEY_FORMAT_TRANSPARENT_SYMMETRIC
        };
        Set<Integer> set = new HashSet<>();
        for (int v : values) set.add(v);
        assertEquals(values.length, set.size(), "KeyFormatType values must be unique");
    }

    // ---- NameType values ----

    @Test
    void nameTypeUninterpretedTextStringIsOne() {
        assertEquals(1, Tag.NAME_TYPE_UNINTERPRETED_TEXT_STRING);
    }

    @Test
    void nameTypeUriIsTwo() {
        assertEquals(2, Tag.NAME_TYPE_URI);
    }

    // ---- UsageMask values ----

    @Test
    void usageSignIs0x01() {
        assertEquals(0x00000001, Tag.USAGE_SIGN);
    }

    @Test
    void usageVerifyIs0x02() {
        assertEquals(0x00000002, Tag.USAGE_VERIFY);
    }

    @Test
    void usageEncryptIs0x04() {
        assertEquals(0x00000004, Tag.USAGE_ENCRYPT);
    }

    @Test
    void usageDecryptIs0x08() {
        assertEquals(0x00000008, Tag.USAGE_DECRYPT);
    }

    @Test
    void usageWrapKeyIs0x10() {
        assertEquals(0x00000010, Tag.USAGE_WRAP_KEY);
    }

    @Test
    void usageUnwrapKeyIs0x20() {
        assertEquals(0x00000020, Tag.USAGE_UNWRAP_KEY);
    }

    @Test
    void usageExportIs0x40() {
        assertEquals(0x00000040, Tag.USAGE_EXPORT);
    }

    @Test
    void usageMacGenerateIs0x80() {
        assertEquals(0x00000080, Tag.USAGE_MAC_GENERATE);
    }

    @Test
    void usageMacVerifyIs0x100() {
        assertEquals(0x00000100, Tag.USAGE_MAC_VERIFY);
    }

    @Test
    void usageDeriveKeyIs0x200() {
        assertEquals(0x00000200, Tag.USAGE_DERIVE_KEY);
    }

    @Test
    void usageKeyAgreementIs0x800() {
        assertEquals(0x00000800, Tag.USAGE_KEY_AGREEMENT);
    }

    @Test
    void usageEncryptDecryptCombineCorrectly() {
        int combined = Tag.USAGE_ENCRYPT | Tag.USAGE_DECRYPT;
        assertEquals(0x0C, combined);
        assertTrue((combined & Tag.USAGE_ENCRYPT) != 0);
        assertTrue((combined & Tag.USAGE_DECRYPT) != 0);
        assertTrue((combined & Tag.USAGE_SIGN) == 0);
    }

    @Test
    void usageMaskBitsDoNotOverlap() {
        int[] values = {
            Tag.USAGE_SIGN, Tag.USAGE_VERIFY, Tag.USAGE_ENCRYPT, Tag.USAGE_DECRYPT,
            Tag.USAGE_WRAP_KEY, Tag.USAGE_UNWRAP_KEY, Tag.USAGE_EXPORT,
            Tag.USAGE_MAC_GENERATE, Tag.USAGE_MAC_VERIFY,
            Tag.USAGE_DERIVE_KEY, Tag.USAGE_KEY_AGREEMENT
        };
        for (int i = 0; i < values.length; i++) {
            for (int j = i + 1; j < values.length; j++) {
                assertEquals(0, values[i] & values[j],
                    String.format("Usage mask bits overlap: 0x%X & 0x%X", values[i], values[j]));
            }
        }
    }

    // ---- All tag values in 0x42XXXX range ----

    // ---- New tag constants ----

    @Test
    void privateKeyUniqueIdentifierTag() {
        assertEquals(0x420066, Tag.PRIVATE_KEY_UNIQUE_IDENTIFIER);
    }

    @Test
    void publicKeyUniqueIdentifierTag() {
        assertEquals(0x42006F, Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER);
    }

    @Test
    void dataTag() {
        assertEquals(0x420033, Tag.DATA);
    }

    @Test
    void ivCounterNonceTag() {
        assertEquals(0x420047, Tag.IV_COUNTER_NONCE);
    }

    @Test
    void signatureDataTag() {
        assertEquals(0x42004F, Tag.SIGNATURE_DATA);
    }

    @Test
    void macDataTag() {
        assertEquals(0x420051, Tag.MAC_DATA);
    }

    @Test
    void validityIndicatorTag() {
        assertEquals(0x420098, Tag.VALIDITY_INDICATOR);
    }

    @Test
    void revocationReasonTag() {
        assertEquals(0x420082, Tag.REVOCATION_REASON);
    }

    @Test
    void revocationReasonCodeTag() {
        assertEquals(0x420083, Tag.REVOCATION_REASON_CODE);
    }

    @Test
    void derivationParametersTag() {
        assertEquals(0x420032, Tag.DERIVATION_PARAMETERS);
    }

    @Test
    void derivationDataTag() {
        assertEquals(0x420030, Tag.DERIVATION_DATA);
    }

    @Test
    void leaseTimeTag() {
        assertEquals(0x420049, Tag.LEASE_TIME);
    }

    @Test
    void stateTag() {
        assertEquals(0x42008D, Tag.STATE);
    }

    @Test
    void allTagFieldsAreIn0x42Range() throws Exception {
        List<String> tagFieldNames = java.util.Arrays.asList(
            "REQUEST_MESSAGE", "RESPONSE_MESSAGE", "REQUEST_HEADER", "RESPONSE_HEADER",
            "PROTOCOL_VERSION", "PROTOCOL_VERSION_MAJOR", "PROTOCOL_VERSION_MINOR",
            "BATCH_COUNT", "BATCH_ITEM", "OPERATION", "REQUEST_PAYLOAD",
            "RESPONSE_PAYLOAD", "RESULT_STATUS", "RESULT_REASON", "RESULT_MESSAGE",
            "UNIQUE_IDENTIFIER", "OBJECT_TYPE", "NAME", "NAME_VALUE", "NAME_TYPE",
            "ATTRIBUTE", "ATTRIBUTE_NAME", "ATTRIBUTE_VALUE",
            "SYMMETRIC_KEY", "KEY_BLOCK", "KEY_FORMAT_TYPE", "KEY_VALUE", "KEY_MATERIAL",
            "CRYPTOGRAPHIC_ALGORITHM", "CRYPTOGRAPHIC_LENGTH", "CRYPTOGRAPHIC_USAGE_MASK",
            "TEMPLATE_ATTRIBUTE",
            "PRIVATE_KEY_UNIQUE_IDENTIFIER", "PUBLIC_KEY_UNIQUE_IDENTIFIER",
            "PUBLIC_KEY", "PRIVATE_KEY",
            "CERTIFICATE", "CERTIFICATE_TYPE", "CERTIFICATE_VALUE",
            "DATA", "IV_COUNTER_NONCE", "SIGNATURE_DATA", "MAC_DATA", "VALIDITY_INDICATOR",
            "REVOCATION_REASON", "REVOCATION_REASON_CODE",
            "QUERY_FUNCTION", "STATE",
            "DERIVATION_METHOD", "DERIVATION_PARAMETERS", "DERIVATION_DATA",
            "LEASE_TIME"
        );
        for (String name : tagFieldNames) {
            Field f = Tag.class.getDeclaredField(name);
            int value = f.getInt(null);
            assertTrue((value & 0xFF0000) == 0x420000,
                String.format("Tag %s (0x%06X) should be in 0x42XXXX range", name, value));
        }
    }

    @Test
    void noTagDuplicates() throws Exception {
        // Collect all static final int fields that are in the 0x42XXXX range (tags)
        Set<Integer> seen = new HashSet<>();
        List<String> duplicates = new ArrayList<>();
        for (Field f : Tag.class.getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers())
                && Modifier.isFinal(f.getModifiers())
                && f.getType() == int.class) {
                int value = f.getInt(null);
                if ((value & 0xFF0000) == 0x420000) {
                    if (!seen.add(value)) {
                        duplicates.add(String.format("%s=0x%06X", f.getName(), value));
                    }
                }
            }
        }
        assertTrue(duplicates.isEmpty(),
            "Duplicate tag values found: " + duplicates);
    }
}
