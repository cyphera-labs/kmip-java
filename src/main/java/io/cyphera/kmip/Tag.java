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

/**
 * KMIP 1.4 tag, type, and enum constants.
 * Only the subset needed for Locate, Get, Create operations.
 *
 * <p>Reference: OASIS KMIP Specification v1.4
 * https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html
 */
public final class Tag {

    private Tag() { }

    // --- Tags ---

    // Message structure
    public static final int REQUEST_MESSAGE        = 0x420078;
    public static final int RESPONSE_MESSAGE       = 0x42007B;
    public static final int REQUEST_HEADER         = 0x420077;
    public static final int RESPONSE_HEADER        = 0x42007A;
    public static final int PROTOCOL_VERSION       = 0x420069;
    public static final int PROTOCOL_VERSION_MAJOR = 0x42006A;
    public static final int PROTOCOL_VERSION_MINOR = 0x42006B;
    public static final int BATCH_COUNT            = 0x42000D;
    public static final int BATCH_ITEM             = 0x42000F;
    public static final int OPERATION              = 0x42005C;
    public static final int REQUEST_PAYLOAD        = 0x420079;
    public static final int RESPONSE_PAYLOAD       = 0x42007C;
    public static final int RESULT_STATUS          = 0x42007F;
    public static final int RESULT_REASON          = 0x420080;
    public static final int RESULT_MESSAGE         = 0x420081;

    // Object identification
    public static final int UNIQUE_IDENTIFIER      = 0x420094;
    public static final int OBJECT_TYPE            = 0x420057;

    // Naming
    public static final int NAME                   = 0x420053;
    public static final int NAME_VALUE             = 0x420055;
    public static final int NAME_TYPE              = 0x420054;

    // Attributes (KMIP 1.x style)
    public static final int ATTRIBUTE              = 0x420008;
    public static final int ATTRIBUTE_NAME         = 0x42000A;
    public static final int ATTRIBUTE_VALUE        = 0x42000B;

    // Key structure
    public static final int SYMMETRIC_KEY          = 0x42008F;
    public static final int KEY_BLOCK              = 0x420040;
    public static final int KEY_FORMAT_TYPE        = 0x420042;
    public static final int KEY_VALUE              = 0x420045;
    public static final int KEY_MATERIAL           = 0x420043;

    // Crypto attributes
    public static final int CRYPTOGRAPHIC_ALGORITHM  = 0x420028;
    public static final int CRYPTOGRAPHIC_LENGTH     = 0x42002A;
    public static final int CRYPTOGRAPHIC_USAGE_MASK = 0x42002C;

    // Template
    public static final int TEMPLATE_ATTRIBUTE     = 0x420091;

    // --- Operations ---

    public static final int OP_CREATE   = 0x00000001;
    public static final int OP_LOCATE   = 0x00000008;
    public static final int OP_GET      = 0x0000000A;
    public static final int OP_ACTIVATE = 0x00000012;
    public static final int OP_DESTROY  = 0x00000014;
    public static final int OP_CHECK    = 0x0000001C;

    // --- Object Types ---

    public static final int OBJ_SYMMETRIC_KEY = 0x00000001;
    public static final int OBJ_PUBLIC_KEY    = 0x00000002;
    public static final int OBJ_PRIVATE_KEY   = 0x00000003;
    public static final int OBJ_CERTIFICATE   = 0x00000006;
    public static final int OBJ_SECRET_DATA   = 0x00000007;
    public static final int OBJ_OPAQUE_DATA   = 0x00000008;

    // --- Result Status ---

    public static final int STATUS_SUCCESS           = 0x00000000;
    public static final int STATUS_OPERATION_FAILED  = 0x00000001;
    public static final int STATUS_OPERATION_PENDING = 0x00000002;
    public static final int STATUS_OPERATION_UNDONE  = 0x00000003;

    // --- Key Format Types ---

    public static final int KEY_FORMAT_RAW                  = 0x00000001;
    public static final int KEY_FORMAT_OPAQUE               = 0x00000002;
    public static final int KEY_FORMAT_PKCS1                = 0x00000003;
    public static final int KEY_FORMAT_PKCS8                = 0x00000004;
    public static final int KEY_FORMAT_X509                 = 0x00000005;
    public static final int KEY_FORMAT_EC_PRIVATE_KEY       = 0x00000006;
    public static final int KEY_FORMAT_TRANSPARENT_SYMMETRIC = 0x00000007;

    // --- Algorithms ---

    public static final int ALG_DES         = 0x00000001;
    public static final int ALG_TRIPLE_DES  = 0x00000002;
    public static final int ALG_AES         = 0x00000003;
    public static final int ALG_RSA         = 0x00000004;
    public static final int ALG_DSA         = 0x00000005;
    public static final int ALG_ECDSA       = 0x00000006;
    public static final int ALG_HMAC_SHA1   = 0x00000007;
    public static final int ALG_HMAC_SHA256 = 0x00000008;
    public static final int ALG_HMAC_SHA384 = 0x00000009;
    public static final int ALG_HMAC_SHA512 = 0x0000000A;

    // --- Name Types ---

    public static final int NAME_TYPE_UNINTERPRETED_TEXT_STRING = 0x00000001;
    public static final int NAME_TYPE_URI                      = 0x00000002;

    // --- Cryptographic Usage Mask (bitmask) ---

    public static final int USAGE_SIGN          = 0x00000001;
    public static final int USAGE_VERIFY        = 0x00000002;
    public static final int USAGE_ENCRYPT       = 0x00000004;
    public static final int USAGE_DECRYPT       = 0x00000008;
    public static final int USAGE_WRAP_KEY      = 0x00000010;
    public static final int USAGE_UNWRAP_KEY    = 0x00000020;
    public static final int USAGE_EXPORT        = 0x00000040;
    public static final int USAGE_DERIVE_KEY    = 0x00000100;
    public static final int USAGE_KEY_AGREEMENT = 0x00000800;
}
