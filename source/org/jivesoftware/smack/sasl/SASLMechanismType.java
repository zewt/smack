/**
 * Copyright 2011 Glenn Maynard
 * Copyright 2003-2007 Jive Software.
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

import org.apache.harmony.javax.security.auth.callback.CallbackHandler;
import org.jivesoftware.smack.XMPPException;

/**
 * The interface for all SASL mechanisms.
 * <p>
 * To add support for mechanisms provided by javax.security.auth, you probably
 * don't want to be here.  See the use of {@link SASLAuthentication#registerSASLMechanism}
 * at the top of {@link SASLAuthentication} instead.
 * <p>
 * This class may be implemented to provide SASL mechanisms through APIs other
 * than javax.security.auth.
 */
public abstract class SASLMechanismType {
    /** This exception is thrown by {@see #authenticate} if this mechanism is not available. */
    static public class MechanismNotSupported extends Exception {};

    private final String mechanismName;

    public SASLMechanismType(String mechanismName) { this.mechanismName = mechanismName; }

    /**
     * Returns the common name of the SASL mechanism. E.g.: PLAIN, DIGEST-MD5 or GSSAPI.
     *
     * @return the common name of the SASL mechanism.
     */
    public final String getName() { return mechanismName; }

    /**
     * Attempt to begin authentication with this mechanism.
     *
     * @return the initial response, or {@code null} if none
     * @throws XMPPException if this mechanism is supported but failed
     * @throws MechanismNotSupported if this mechanism is unsupported by the local system.
     */
    public abstract byte[] authenticate(String username, String host, String password)
        throws XMPPException, MechanismNotSupported;

    /** See {@link #authenticate(String, String, String)}. */
    public abstract byte[] authenticate(String username, String host, CallbackHandler cbh)
        throws XMPPException, MechanismNotSupported;

    /**
     * A SASL challenge has been received.  Return the response.
     */
    public abstract byte[] challengeReceived(byte[] challenge) throws XMPPException;

    static abstract public class Factory {
        String name;
        public Factory(String name) { this.name = name; }
        public String getName() { return name; }
        public abstract SASLMechanismType create();
    }
};
