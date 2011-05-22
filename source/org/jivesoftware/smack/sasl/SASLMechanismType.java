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

import java.io.IOException;

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
    static public class MechanismNotSupported extends Exception {};

    private final String mechanismName;

    public SASLMechanismType(String mechanismName) { this.mechanismName = mechanismName; }

    /**
     * Returns the common name of the SASL mechanism. E.g.: PLAIN, DIGEST-MD5 or GSSAPI.
     *
     * @return the common name of the SASL mechanism.
     */
    public final String getName() { return mechanismName; }

    public abstract String authenticate(String username, String host, String password)
        throws IOException, XMPPException, MechanismNotSupported;

    public abstract String authenticate(String username, String host, CallbackHandler cbh)
        throws IOException, XMPPException, MechanismNotSupported;

    public abstract byte[] challengeReceived(byte[] challenge) throws IOException;

    static abstract public class Factory {
        String name;
        public Factory(String name) { this.name = name; }
        public String getName() { return name; }
        public abstract SASLMechanismType create();
    }
};
