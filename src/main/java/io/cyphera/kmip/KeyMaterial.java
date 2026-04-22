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

import java.util.Arrays;

/**
 * Wraps raw key material bytes with secure zeroing on close.
 *
 * <p>Callers should use try-with-resources to ensure key bytes
 * are zeroed promptly when no longer needed.
 */
public final class KeyMaterial implements AutoCloseable {

    private byte[] data;
    private boolean closed;

    public KeyMaterial(byte[] data) {
        this.data = data != null ? data.clone() : new byte[0];
        this.closed = false;
    }

    /**
     * Returns the raw key bytes. Throws if already closed.
     */
    public byte[] getBytes() {
        if (closed) {
            throw new IllegalStateException("KeyMaterial has been closed");
        }
        return data;
    }

    /**
     * Returns the length of the key material in bytes.
     */
    public int length() {
        if (closed) {
            throw new IllegalStateException("KeyMaterial has been closed");
        }
        return data.length;
    }

    /**
     * Zeroes the key material bytes and marks this instance as closed.
     */
    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(data, (byte) 0);
            closed = true;
        }
    }
}
