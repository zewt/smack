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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.harmony.javax.security.auth.callback.Callback;
import org.apache.harmony.javax.security.auth.callback.CallbackHandler;
import org.apache.harmony.javax.security.auth.callback.PasswordCallback;
import org.apache.harmony.javax.security.auth.callback.UnsupportedCallbackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.util.Base64;

public class SASLHelpers {
    /** Create an SHA-1 HMAC object, with the given data as the key. */
    public static Mac createMac(byte[] keyData) throws XMPPException {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            Key key = new SecretKeySpec(keyData, "HmacSHA1");
            mac.init(key);
            return mac;
        } catch(NoSuchAlgorithmException e) {
            throw new XMPPException(e);
        } catch (InvalidKeyException e) {
            throw new XMPPException(e);
        }
    }

    /** Compute the HMAC-SHA-1 of the given data, using the given key. */
    public static byte[] computeHMACSHA1(byte[] key, byte[] data) throws XMPPException {
        Mac hmac = SASLHelpers.createMac(key);
        hmac.update(data);
        return hmac.doFinal();
    }

    /** Request the password from a CallbackHandler. */
    public static String requestPassword(CallbackHandler cbh) throws XMPPException {
        PasswordCallback pcb = new PasswordCallback("Password:", false);

        Callback[] callbacks = new Callback[1];
        callbacks[0] = pcb;
        try {
            cbh.handle(callbacks);
        } catch (IOException e) {
            throw new XMPPException(e);
        } catch (UnsupportedCallbackException e) {
            throw new XMPPException(e);
        }

        return new String(pcb.getPassword());
    }

    /** Compute the SHA-1 hash of a block of data. */
    public static byte[] computeSHA1(byte[] data) throws XMPPException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new XMPPException(e);
        }

        digest.update(data);
        return digest.digest();
    }

    public static byte[] decodeBase64(String s) throws XMPPException {
        byte[] bytes = s.getBytes();
        byte[] decoded = Base64.decode(bytes, 0, bytes.length, 0);
        if(decoded == null)
            throw new XMPPException("Couldn't decode SCRAM data: " + s);
        return decoded;
    }
}
