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

class TtlvTest {

    @Test
    void encodesAndDecodesInteger() {
        byte[] encoded = encodeInteger(0x42006A, 1);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x42006A, decoded.tag);
        assertEquals(TYPE_INTEGER, decoded.type);
        assertEquals(1, decoded.intValue());
    }

    @Test
    void encodesAndDecodesEnumeration() {
        byte[] encoded = encodeEnum(0x42005C, 0x0000000A);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x42005C, decoded.tag);
        assertEquals(TYPE_ENUMERATION, decoded.type);
        assertEquals(0x0000000A, decoded.intValue());
    }

    @Test
    void encodesAndDecodesTextString() {
        byte[] encoded = encodeTextString(0x420055, "my-key");
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x420055, decoded.tag);
        assertEquals(TYPE_TEXT_STRING, decoded.type);
        assertEquals("my-key", decoded.stringValue());
    }

    @Test
    void encodesAndDecodesByteString() {
        byte[] key = new byte[]{(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD};
        byte[] encoded = encodeByteString(0x420043, key);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x420043, decoded.tag);
        assertEquals(TYPE_BYTE_STRING, decoded.type);
        assertArrayEquals(key, decoded.bytesValue());
    }

    @Test
    void encodesAndDecodesBoolean() {
        byte[] encoded = encodeBoolean(0x420008, true);
        Item decoded = decodeTTLV(encoded);
        assertEquals(TYPE_BOOLEAN, decoded.type);
        assertTrue(decoded.boolValue());
    }

    @Test
    void encodesAndDecodesStructureWithChildren() {
        byte[] encoded = encodeStructure(0x420069,
            encodeInteger(0x42006A, 1),
            encodeInteger(0x42006B, 4)
        );
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x420069, decoded.tag);
        assertEquals(TYPE_STRUCTURE, decoded.type);
        assertEquals(2, decoded.children().size());
        assertEquals(1, decoded.children().get(0).intValue());
        assertEquals(4, decoded.children().get(1).intValue());
    }

    @Test
    void findChildLocatesChildByTag() {
        byte[] encoded = encodeStructure(0x420069,
            encodeInteger(0x42006A, 1),
            encodeInteger(0x42006B, 4)
        );
        Item decoded = decodeTTLV(encoded);
        Item child = findChild(decoded, 0x42006B);
        assertNotNull(child);
        assertEquals(4, child.intValue());
    }

    @Test
    void padsTextStringsToEightByteAlignment() {
        // "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
        byte[] encoded = encodeTextString(0x420055, "hello");
        assertEquals(16, encoded.length); // 8 header + 8 padded value
    }

    @Test
    void handlesEmptyTextString() {
        byte[] encoded = encodeTextString(0x420055, "");
        Item decoded = decodeTTLV(encoded);
        assertEquals("", decoded.stringValue());
    }

    @Test
    void roundTripsNestedStructures() {
        byte[] encoded = encodeStructure(0x420078,
            encodeStructure(0x420077,
                encodeStructure(0x420069,
                    encodeInteger(0x42006A, 1),
                    encodeInteger(0x42006B, 4)
                ),
                encodeInteger(0x42000D, 1)
            )
        );
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x420078, decoded.tag);
        Item header = findChild(decoded, 0x420077);
        assertNotNull(header);
        Item version = findChild(header, 0x420069);
        assertNotNull(version);
        Item major = findChild(version, 0x42006A);
        assertNotNull(major);
        assertEquals(1, major.intValue());
    }
}
