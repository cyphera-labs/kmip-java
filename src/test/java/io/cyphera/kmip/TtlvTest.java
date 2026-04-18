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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static io.cyphera.kmip.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

class TtlvTest {

    // ---- Integer encoding/decoding ----

    @Test
    void encodesAndDecodesPositiveInteger() {
        byte[] encoded = encodeInteger(0x42006A, 42);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x42006A, decoded.tag);
        assertEquals(TYPE_INTEGER, decoded.type);
        assertEquals(42, decoded.intValue());
    }

    @Test
    void encodesAndDecodesNegativeInteger() {
        byte[] encoded = encodeInteger(0x42006A, -1);
        Item decoded = decodeTTLV(encoded);
        assertEquals(-1, decoded.intValue());
    }

    @Test
    void encodesAndDecodesZeroInteger() {
        byte[] encoded = encodeInteger(0x42006A, 0);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0, decoded.intValue());
    }

    @Test
    void encodesAndDecodesMinInteger() {
        byte[] encoded = encodeInteger(0x42006A, Integer.MIN_VALUE);
        Item decoded = decodeTTLV(encoded);
        assertEquals(Integer.MIN_VALUE, decoded.intValue());
    }

    @Test
    void encodesAndDecodesMaxInteger() {
        byte[] encoded = encodeInteger(0x42006A, Integer.MAX_VALUE);
        Item decoded = decodeTTLV(encoded);
        assertEquals(Integer.MAX_VALUE, decoded.intValue());
    }

    @Test
    void integerTotalLengthIs16() {
        // 4-byte value padded to 8 => 8 header + 8 value = 16
        byte[] encoded = encodeInteger(0x42006A, 1);
        assertEquals(16, encoded.length);
        Item decoded = decodeTTLV(encoded);
        assertEquals(4, decoded.length);
        assertEquals(16, decoded.totalLength);
    }

    // ---- Long integer encoding/decoding ----

    @Test
    void encodesAndDecodesPositiveLongInteger() {
        byte[] encoded = encodeLongInteger(0x420094, 123456789012345L);
        Item decoded = decodeTTLV(encoded);
        assertEquals(TYPE_LONG_INTEGER, decoded.type);
        assertEquals(123456789012345L, decoded.longValue());
    }

    @Test
    void encodesAndDecodesNegativeLongInteger() {
        byte[] encoded = encodeLongInteger(0x420094, -99999999999L);
        Item decoded = decodeTTLV(encoded);
        assertEquals(-99999999999L, decoded.longValue());
    }

    @Test
    void longIntegerTotalLengthIs16() {
        byte[] encoded = encodeLongInteger(0x420094, 1L);
        assertEquals(16, encoded.length);
    }

    // ---- Enumeration encoding/decoding ----

    @Test
    void encodesAndDecodesEnumeration() {
        byte[] encoded = encodeEnum(0x42005C, 0x0000000A);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x42005C, decoded.tag);
        assertEquals(TYPE_ENUMERATION, decoded.type);
        assertEquals(0x0000000A, decoded.intValue());
    }

    @Test
    void enumerationTotalLengthIs16() {
        byte[] encoded = encodeEnum(0x42005C, 1);
        assertEquals(16, encoded.length);
        Item decoded = decodeTTLV(encoded);
        assertEquals(4, decoded.length);
        assertEquals(16, decoded.totalLength);
    }

    // ---- Boolean encoding/decoding ----

    @Test
    void encodesAndDecodesBooleanTrue() {
        byte[] encoded = encodeBoolean(0x420008, true);
        Item decoded = decodeTTLV(encoded);
        assertEquals(TYPE_BOOLEAN, decoded.type);
        assertTrue(decoded.boolValue());
    }

    @Test
    void encodesAndDecodesBooleanFalse() {
        byte[] encoded = encodeBoolean(0x420008, false);
        Item decoded = decodeTTLV(encoded);
        assertEquals(TYPE_BOOLEAN, decoded.type);
        assertFalse(decoded.boolValue());
    }

    @Test
    void booleanTotalLengthIs16() {
        byte[] encoded = encodeBoolean(0x420008, true);
        assertEquals(16, encoded.length);
        Item decoded = decodeTTLV(encoded);
        assertEquals(8, decoded.length);
        assertEquals(16, decoded.totalLength);
    }

    // ---- Text string encoding/decoding ----

    @Test
    void encodesAndDecodesTextString() {
        byte[] encoded = encodeTextString(0x420055, "my-key");
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x420055, decoded.tag);
        assertEquals(TYPE_TEXT_STRING, decoded.type);
        assertEquals("my-key", decoded.stringValue());
    }

    @Test
    void handlesEmptyTextString() {
        byte[] encoded = encodeTextString(0x420055, "");
        Item decoded = decodeTTLV(encoded);
        assertEquals("", decoded.stringValue());
        assertEquals(0, decoded.length);
    }

    @Test
    void textStringFiveBytesRoundsToEight() {
        // "hello" = 5 bytes -> padded to 8 -> total 16
        byte[] encoded = encodeTextString(0x420055, "hello");
        assertEquals(16, encoded.length);
        Item decoded = decodeTTLV(encoded);
        assertEquals(5, decoded.length);
    }

    @Test
    void textStringEightBytesNoPaddingNeeded() {
        // "12345678" = 8 bytes -> padded to 8 -> total 16
        byte[] encoded = encodeTextString(0x420055, "12345678");
        assertEquals(16, encoded.length);
        Item decoded = decodeTTLV(encoded);
        assertEquals(8, decoded.length);
    }

    @Test
    void textStringNineBytesRoundsToSixteen() {
        // "123456789" = 9 bytes -> padded to 16 -> total 24
        byte[] encoded = encodeTextString(0x420055, "123456789");
        assertEquals(24, encoded.length);
        Item decoded = decodeTTLV(encoded);
        assertEquals(9, decoded.length);
    }

    @Test
    void textStringPaddingBytesAreZero() {
        // "hi" = 2 bytes, padded to 8 => 6 padding bytes, all zero
        byte[] encoded = encodeTextString(0x420055, "hi");
        for (int i = 10; i < 16; i++) {
            assertEquals(0, encoded[i], "Padding byte at index " + i + " should be 0");
        }
    }

    @Test
    void encodesAndDecodesUnicodeTextString() {
        String unicode = "\u00e9\u00e0\u00fc"; // multi-byte UTF-8
        byte[] encoded = encodeTextString(0x420055, unicode);
        Item decoded = decodeTTLV(encoded);
        assertEquals(unicode, decoded.stringValue());
    }

    @Test
    void encodesAndDecodesLongTextString() {
        String longStr = "A".repeat(300);
        byte[] encoded = encodeTextString(0x420055, longStr);
        Item decoded = decodeTTLV(encoded);
        assertEquals(longStr, decoded.stringValue());
        assertEquals(300, decoded.length);
    }

    // ---- Byte string encoding/decoding ----

    @Test
    void encodesAndDecodesByteString() {
        byte[] key = {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD};
        byte[] encoded = encodeByteString(0x420043, key);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x420043, decoded.tag);
        assertEquals(TYPE_BYTE_STRING, decoded.type);
        assertArrayEquals(key, decoded.bytesValue());
    }

    @Test
    void byteStringPaddedToAlignment() {
        byte[] value = {0x01, 0x02, 0x03}; // 3 bytes -> padded to 8
        byte[] encoded = encodeByteString(0x420043, value);
        assertEquals(16, encoded.length);
    }

    @Test
    void emptyByteString() {
        byte[] encoded = encodeByteString(0x420043, new byte[0]);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0, decoded.bytesValue().length);
        assertEquals(0, decoded.length);
    }

    // ---- DateTime encoding/decoding ----

    @Test
    void encodesAndDecodesDateTime() {
        long epoch = 1609459200L; // 2021-01-01 00:00:00 UTC
        byte[] encoded = encodeDateTime(0x420008, epoch);
        Item decoded = decodeTTLV(encoded);
        assertEquals(TYPE_DATE_TIME, decoded.type);
        assertEquals(epoch, decoded.longValue());
    }

    @Test
    void dateTimeTotalLengthIs16() {
        byte[] encoded = encodeDateTime(0x420008, 0L);
        assertEquals(16, encoded.length);
    }

    // ---- Interval encoding ----

    @Test
    void encodesAndDecodesInterval() {
        // Interval is 4-byte integer type 0x0A
        byte[] buf = new byte[4];
        ByteBuffer.wrap(buf).putInt(3600);
        byte[] encoded = encodeTTLV(0x420008, TYPE_INTERVAL, buf);
        Item decoded = decodeTTLV(encoded);
        assertEquals(TYPE_INTERVAL, decoded.type);
        assertEquals(3600, decoded.intValue());
    }

    // ---- Structure encoding/decoding ----

    @Test
    void encodesAndDecodesEmptyStructure() {
        byte[] encoded = encodeStructure(0x420069);
        Item decoded = decodeTTLV(encoded);
        assertEquals(0x420069, decoded.tag);
        assertEquals(TYPE_STRUCTURE, decoded.type);
        assertEquals(0, decoded.children().size());
        assertEquals(0, decoded.length);
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
    void encodesAndDecodesStructureWithMixedTypes() {
        byte[] encoded = encodeStructure(0x420069,
            encodeInteger(0x42006A, 42),
            encodeTextString(0x420055, "test"),
            encodeBoolean(0x420008, true),
            encodeEnum(0x42005C, 3)
        );
        Item decoded = decodeTTLV(encoded);
        assertEquals(4, decoded.children().size());
        assertEquals(TYPE_INTEGER, decoded.children().get(0).type);
        assertEquals(TYPE_TEXT_STRING, decoded.children().get(1).type);
        assertEquals(TYPE_BOOLEAN, decoded.children().get(2).type);
        assertEquals(TYPE_ENUMERATION, decoded.children().get(3).type);
    }

    @Test
    void decodesThreeLevelsDeepStructure() {
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
        Item minor = findChild(version, 0x42006B);
        assertNotNull(minor);
        assertEquals(4, minor.intValue());
    }

    // ---- findChild ----

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
    void findChildReturnsNullWhenNotFound() {
        byte[] encoded = encodeStructure(0x420069,
            encodeInteger(0x42006A, 1)
        );
        Item decoded = decodeTTLV(encoded);
        Item child = findChild(decoded, 0x42FFFF);
        assertNull(child);
    }

    @Test
    void findChildReturnsNullOnNonStructure() {
        byte[] encoded = encodeInteger(0x42006A, 42);
        Item decoded = decodeTTLV(encoded);
        Item child = findChild(decoded, 0x42006A);
        assertNull(child);
    }

    // ---- findChildren ----

    @Test
    void findChildrenReturnsMultipleMatches() {
        byte[] encoded = encodeStructure(0x420069,
            encodeTextString(0x420094, "id-1"),
            encodeTextString(0x420094, "id-2"),
            encodeTextString(0x420094, "id-3")
        );
        Item decoded = decodeTTLV(encoded);
        List<Item> matches = findChildren(decoded, 0x420094);
        assertEquals(3, matches.size());
        assertEquals("id-1", matches.get(0).stringValue());
        assertEquals("id-2", matches.get(1).stringValue());
        assertEquals("id-3", matches.get(2).stringValue());
    }

    @Test
    void findChildrenReturnsEmptyWhenNoMatch() {
        byte[] encoded = encodeStructure(0x420069,
            encodeInteger(0x42006A, 1)
        );
        Item decoded = decodeTTLV(encoded);
        List<Item> matches = findChildren(decoded, 0x42FFFF);
        assertTrue(matches.isEmpty());
    }

    @Test
    void findChildrenReturnsEmptyOnNonStructure() {
        byte[] encoded = encodeInteger(0x42006A, 1);
        Item decoded = decodeTTLV(encoded);
        List<Item> matches = findChildren(decoded, 0x42006A);
        assertTrue(matches.isEmpty());
    }

    // ---- Wire format ----

    @Test
    void tagBytesAreBigEndian() {
        byte[] encoded = encodeInteger(0x42006A, 0);
        assertEquals(0x42, encoded[0] & 0xFF);
        assertEquals(0x00, encoded[1] & 0xFF);
        assertEquals(0x6A, encoded[2] & 0xFF);
    }

    @Test
    void typeByteValues() {
        assertEquals(0x01, TYPE_STRUCTURE);
        assertEquals(0x02, TYPE_INTEGER);
        assertEquals(0x03, TYPE_LONG_INTEGER);
        assertEquals(0x04, TYPE_BIG_INTEGER);
        assertEquals(0x05, TYPE_ENUMERATION);
        assertEquals(0x06, TYPE_BOOLEAN);
        assertEquals(0x07, TYPE_TEXT_STRING);
        assertEquals(0x08, TYPE_BYTE_STRING);
        assertEquals(0x09, TYPE_DATE_TIME);
        assertEquals(0x0A, TYPE_INTERVAL);
    }

    @Test
    void typeByteInEncodedOutput() {
        byte[] intEncoded = encodeInteger(0x42006A, 0);
        assertEquals(TYPE_INTEGER, intEncoded[3] & 0xFF);

        byte[] enumEncoded = encodeEnum(0x42005C, 0);
        assertEquals(TYPE_ENUMERATION, enumEncoded[3] & 0xFF);

        byte[] boolEncoded = encodeBoolean(0x420008, true);
        assertEquals(TYPE_BOOLEAN, boolEncoded[3] & 0xFF);

        byte[] strEncoded = encodeTextString(0x420055, "x");
        assertEquals(TYPE_TEXT_STRING, strEncoded[3] & 0xFF);
    }

    @Test
    void lengthFieldIsCorrect() {
        byte[] encoded = encodeInteger(0x42006A, 1);
        // length field at bytes 4-7, integer value length = 4
        int length = ByteBuffer.wrap(encoded, 4, 4).getInt();
        assertEquals(4, length);
    }

    @Test
    void lengthFieldForTextString() {
        byte[] encoded = encodeTextString(0x420055, "hello");
        int length = ByteBuffer.wrap(encoded, 4, 4).getInt();
        assertEquals(5, length); // actual length, not padded
    }

    @Test
    void paddingBytesAreZeroForInteger() {
        byte[] encoded = encodeInteger(0x42006A, 1);
        // integer is 4 bytes at offset 8-11, padding at 12-15
        for (int i = 12; i < 16; i++) {
            assertEquals(0, encoded[i], "Padding byte at " + i);
        }
    }

    // ---- Error handling ----

    @Test
    void throwsOnBufferTooShort() {
        byte[] tooShort = new byte[]{0x42, 0x00, 0x6A};
        assertThrows(IllegalArgumentException.class, () -> decodeTTLV(tooShort));
    }

    @Test
    void throwsOnEmptyBuffer() {
        assertThrows(IllegalArgumentException.class, () -> decodeTTLV(new byte[0]));
    }

    // ---- children() on non-structure ----

    @Test
    void childrenReturnsEmptyListOnNonStructure() {
        byte[] encoded = encodeInteger(0x42006A, 1);
        Item decoded = decodeTTLV(encoded);
        assertTrue(decoded.children().isEmpty());
    }
}
