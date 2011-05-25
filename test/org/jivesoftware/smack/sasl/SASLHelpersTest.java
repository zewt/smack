/**
 * Copyright 2011 Glenn Maynard
 *
 * All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
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

package org.jivesoftware.smack.sasl;

import org.junit.Test;
import static org.junit.Assert.*;
import javax.crypto.Mac;

public class SASLHelpersTest {
    @Test public void createMac() throws Exception {
        Mac mac = SASLHelpers.createMac("test".getBytes());
        assertNotNull(mac);
        assertEquals(mac.getAlgorithm(), "HmacSHA1");
    }

    static void assertArrayEquals(int[] expect, byte[] actual) {
        assertEquals(expect.length, actual.length);

        for(int i = 0; i < expect.length; ++i) {
            // Java mysteriously lacks an unsigned byte type, so convert it.
            int val = actual[i];
            if(val < 0)
                val = 256 + val;
            assertEquals(expect[i], val);
        }
    }

    @Test public void computeHMAC() throws Exception {
        byte[] result = SASLHelpers.computeHMACSHA1("key".getBytes(), "test".getBytes());

        // Python:
        // import hmac, hashlib
        // h = hmac.new("key", "test", hashlib.sha1).digest()
        // ", ".join(["0x%02x" % ord(i) for i in h])
        int[] expect = new int[] {
            0x67, 0x1f, 0x54, 0xce, 0x0c, 0x54, 0x0f, 0x78, 0xff, 0xe1, 0xe2, 0x6d, 0xcf, 0x9c, 0x2a, 0x04, 0x7a, 0xea, 0x4f, 0xda
        };

        assertArrayEquals(expect, result);
    }

    @Test public void computeSHA1() throws Exception {
        byte[] result = SASLHelpers.computeSHA1("test".getBytes());

        int[] expect = new int[] {
            0xa9, 0x4a, 0x8f, 0xe5, 0xcc, 0xb1, 0x9b, 0xa6, 0x1c, 0x4c, 0x08, 0x73, 0xd3, 0x91, 0xe9, 0x87, 0x98, 0x2f, 0xbb, 0xd3
        };

        assertArrayEquals(expect, result);
    }

    @Test public void decodeBase64() throws Exception {
        byte[] result = SASLHelpers.decodeBase64("dGVzdA==");
        String resultString = new String(result, "ASCII");
        assertEquals(resultString, "test");
    }
}
