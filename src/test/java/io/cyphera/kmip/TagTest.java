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
    void operationValuesAreUnique() {
        int[] values = {
            Tag.OP_CREATE, Tag.OP_LOCATE, Tag.OP_GET,
            Tag.OP_ACTIVATE, Tag.OP_DESTROY, Tag.OP_CHECK
        };
        Set<Integer> set = new HashSet<>();
        for (int v : values) set.add(v);
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
    void algorithmHmacSha256IsEight() {
        assertEquals(8, Tag.ALG_HMAC_SHA256);
    }

    @Test
    void algorithmHmacSha384IsNine() {
        assertEquals(9, Tag.ALG_HMAC_SHA384);
    }

    @Test
    void algorithmHmacSha512Is0xA() {
        assertEquals(0x0A, Tag.ALG_HMAC_SHA512);
    }

    @Test
    void algorithmValuesAreUnique() {
        int[] values = {
            Tag.ALG_DES, Tag.ALG_TRIPLE_DES, Tag.ALG_AES, Tag.ALG_RSA,
            Tag.ALG_DSA, Tag.ALG_ECDSA, Tag.ALG_HMAC_SHA1, Tag.ALG_HMAC_SHA256,
            Tag.ALG_HMAC_SHA384, Tag.ALG_HMAC_SHA512
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
    void usageDeriveKeyIs0x100() {
        assertEquals(0x00000100, Tag.USAGE_DERIVE_KEY);
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

    @Test
    void allTagFieldsAreIn0x42Range() throws Exception {
        List<String> tagFieldNames = List.of(
            "REQUEST_MESSAGE", "RESPONSE_MESSAGE", "REQUEST_HEADER", "RESPONSE_HEADER",
            "PROTOCOL_VERSION", "PROTOCOL_VERSION_MAJOR", "PROTOCOL_VERSION_MINOR",
            "BATCH_COUNT", "BATCH_ITEM", "OPERATION", "REQUEST_PAYLOAD",
            "RESPONSE_PAYLOAD", "RESULT_STATUS", "RESULT_REASON", "RESULT_MESSAGE",
            "UNIQUE_IDENTIFIER", "OBJECT_TYPE", "NAME", "NAME_VALUE", "NAME_TYPE",
            "ATTRIBUTE", "ATTRIBUTE_NAME", "ATTRIBUTE_VALUE",
            "SYMMETRIC_KEY", "KEY_BLOCK", "KEY_FORMAT_TYPE", "KEY_VALUE", "KEY_MATERIAL",
            "CRYPTOGRAPHIC_ALGORITHM", "CRYPTOGRAPHIC_LENGTH", "CRYPTOGRAPHIC_USAGE_MASK",
            "TEMPLATE_ATTRIBUTE"
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
