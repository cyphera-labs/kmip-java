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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * TTLV (Tag-Type-Length-Value) encoder/decoder for KMIP.
 * Implements the OASIS KMIP 1.4 binary encoding.
 *
 * <p>Each TTLV item:
 * <ul>
 *   <li>Tag:    3 bytes (identifies the field)</li>
 *   <li>Type:   1 byte  (data type)</li>
 *   <li>Length: 4 bytes  (value length in bytes)</li>
 *   <li>Value:  variable (padded to 8-byte alignment)</li>
 * </ul>
 */
public final class Ttlv {

    // KMIP data types
    public static final int TYPE_STRUCTURE    = 0x01;
    public static final int TYPE_INTEGER      = 0x02;
    public static final int TYPE_LONG_INTEGER = 0x03;
    public static final int TYPE_BIG_INTEGER  = 0x04;
    public static final int TYPE_ENUMERATION  = 0x05;
    public static final int TYPE_BOOLEAN      = 0x06;
    public static final int TYPE_TEXT_STRING   = 0x07;
    public static final int TYPE_BYTE_STRING   = 0x08;
    public static final int TYPE_DATE_TIME    = 0x09;
    public static final int TYPE_INTERVAL     = 0x0A;

    private Ttlv() { }

    /**
     * A decoded TTLV item.
     */
    public static final class Item {
        public final int tag;
        public final int type;
        public final Object value;
        public final int length;
        public final int totalLength;

        public Item(int tag, int type, Object value, int length, int totalLength) {
            this.tag = tag;
            this.type = type;
            this.value = value;
            this.length = length;
            this.totalLength = totalLength;
        }

        /** Get children (only valid for Structure type). */
        @SuppressWarnings("unchecked")
        public List<Item> children() {
            if (type != TYPE_STRUCTURE) {
                return List.of();
            }
            return (List<Item>) value;
        }

        /** Get integer value. */
        public int intValue() {
            return ((Number) value).intValue();
        }

        /** Get long value. */
        public long longValue() {
            return ((Number) value).longValue();
        }

        /** Get boolean value. */
        public boolean boolValue() {
            return (Boolean) value;
        }

        /** Get string value. */
        public String stringValue() {
            return (String) value;
        }

        /** Get byte array value. */
        public byte[] bytesValue() {
            return (byte[]) value;
        }
    }

    // --- Encoding ---

    /**
     * Encode a TTLV item to a byte array.
     *
     * @param tag   3-byte tag value (e.g., 0x420069)
     * @param type  1-byte type value
     * @param value raw value bytes
     * @return encoded TTLV bytes
     */
    public static byte[] encodeTTLV(int tag, int type, byte[] value) {
        int valueLen = value.length;
        int padded = ((valueLen + 7) / 8) * 8;
        byte[] buf = new byte[8 + padded];

        // Tag: 3 bytes big-endian
        buf[0] = (byte) ((tag >> 16) & 0xFF);
        buf[1] = (byte) ((tag >> 8) & 0xFF);
        buf[2] = (byte) (tag & 0xFF);

        // Type: 1 byte
        buf[3] = (byte) type;

        // Length: 4 bytes big-endian
        buf[4] = (byte) ((valueLen >> 24) & 0xFF);
        buf[5] = (byte) ((valueLen >> 16) & 0xFF);
        buf[6] = (byte) ((valueLen >> 8) & 0xFF);
        buf[7] = (byte) (valueLen & 0xFF);

        // Value + padding (padding bytes are already zero)
        System.arraycopy(value, 0, buf, 8, valueLen);

        return buf;
    }

    /**
     * Encode a Structure (type 0x01) containing child TTLV items.
     */
    public static byte[] encodeStructure(int tag, byte[]... children) {
        int totalLen = 0;
        for (byte[] child : children) {
            totalLen += child.length;
        }
        byte[] inner = new byte[totalLen];
        int pos = 0;
        for (byte[] child : children) {
            System.arraycopy(child, 0, inner, pos, child.length);
            pos += child.length;
        }
        return encodeTTLV(tag, TYPE_STRUCTURE, inner);
    }

    /**
     * Encode a 32-bit integer.
     */
    public static byte[] encodeInteger(int tag, int value) {
        byte[] buf = new byte[4];
        ByteBuffer.wrap(buf).putInt(value);
        return encodeTTLV(tag, TYPE_INTEGER, buf);
    }

    /**
     * Encode a 64-bit long integer.
     */
    public static byte[] encodeLongInteger(int tag, long value) {
        byte[] buf = new byte[8];
        ByteBuffer.wrap(buf).putLong(value);
        return encodeTTLV(tag, TYPE_LONG_INTEGER, buf);
    }

    /**
     * Encode an enumeration (32-bit).
     */
    public static byte[] encodeEnum(int tag, int value) {
        byte[] buf = new byte[4];
        ByteBuffer.wrap(buf).putInt(value);
        return encodeTTLV(tag, TYPE_ENUMERATION, buf);
    }

    /**
     * Encode a boolean.
     */
    public static byte[] encodeBoolean(int tag, boolean value) {
        byte[] buf = new byte[8];
        ByteBuffer.wrap(buf).putLong(value ? 1L : 0L);
        return encodeTTLV(tag, TYPE_BOOLEAN, buf);
    }

    /**
     * Encode a text string (UTF-8).
     */
    public static byte[] encodeTextString(int tag, String value) {
        return encodeTTLV(tag, TYPE_TEXT_STRING, value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encode a byte string (raw bytes).
     */
    public static byte[] encodeByteString(int tag, byte[] value) {
        return encodeTTLV(tag, TYPE_BYTE_STRING, value);
    }

    /**
     * Encode a DateTime (64-bit POSIX time in seconds).
     */
    public static byte[] encodeDateTime(int tag, long epochSeconds) {
        byte[] buf = new byte[8];
        ByteBuffer.wrap(buf).putLong(epochSeconds);
        return encodeTTLV(tag, TYPE_DATE_TIME, buf);
    }

    // --- Decoding ---

    /**
     * Decode a TTLV buffer into a parsed tree.
     *
     * @param data   raw TTLV bytes
     * @param offset starting offset
     * @return decoded Item
     */
    public static Item decodeTTLV(byte[] data, int offset) {
        if (data.length - offset < 8) {
            throw new IllegalArgumentException("TTLV buffer too short for header");
        }

        int tag = ((data[offset] & 0xFF) << 16)
                | ((data[offset + 1] & 0xFF) << 8)
                | (data[offset + 2] & 0xFF);
        int type = data[offset + 3] & 0xFF;
        int length = ByteBuffer.wrap(data, offset + 4, 4).getInt();
        int padded = ((length + 7) / 8) * 8;
        int totalLength = 8 + padded;
        int valueStart = offset + 8;

        Object value;
        switch (type) {
            case TYPE_STRUCTURE: {
                List<Item> children = new ArrayList<>();
                int pos = valueStart;
                int end = valueStart + length;
                while (pos < end) {
                    Item child = decodeTTLV(data, pos);
                    children.add(child);
                    pos += child.totalLength;
                }
                value = children;
                break;
            }
            case TYPE_INTEGER:
                value = ByteBuffer.wrap(data, valueStart, 4).getInt();
                break;
            case TYPE_LONG_INTEGER:
                value = ByteBuffer.wrap(data, valueStart, 8).getLong();
                break;
            case TYPE_ENUMERATION:
                value = ByteBuffer.wrap(data, valueStart, 4).getInt();
                break;
            case TYPE_BOOLEAN:
                value = ByteBuffer.wrap(data, valueStart, 8).getLong() != 0;
                break;
            case TYPE_TEXT_STRING:
                value = new String(data, valueStart, length, StandardCharsets.UTF_8);
                break;
            case TYPE_BYTE_STRING: {
                byte[] bytes = new byte[length];
                System.arraycopy(data, valueStart, bytes, 0, length);
                value = bytes;
                break;
            }
            case TYPE_DATE_TIME:
                value = ByteBuffer.wrap(data, valueStart, 8).getLong();
                break;
            case TYPE_BIG_INTEGER: {
                byte[] bytes = new byte[length];
                System.arraycopy(data, valueStart, bytes, 0, length);
                value = bytes;
                break;
            }
            case TYPE_INTERVAL:
                value = ByteBuffer.wrap(data, valueStart, 4).getInt();
                break;
            default: {
                byte[] bytes = new byte[length];
                System.arraycopy(data, valueStart, bytes, 0, length);
                value = bytes;
                break;
            }
        }

        return new Item(tag, type, value, length, totalLength);
    }

    /**
     * Decode a TTLV buffer from offset 0.
     */
    public static Item decodeTTLV(byte[] data) {
        return decodeTTLV(data, 0);
    }

    /**
     * Find a child item by tag within a decoded structure.
     */
    public static Item findChild(Item decoded, int tag) {
        if (decoded.type != TYPE_STRUCTURE) {
            return null;
        }
        for (Item child : decoded.children()) {
            if (child.tag == tag) {
                return child;
            }
        }
        return null;
    }

    /**
     * Find all children by tag within a decoded structure.
     */
    public static List<Item> findChildren(Item decoded, int tag) {
        List<Item> result = new ArrayList<>();
        if (decoded.type != TYPE_STRUCTURE) {
            return result;
        }
        for (Item child : decoded.children()) {
            if (child.tag == tag) {
                result.add(child);
            }
        }
        return result;
    }
}
