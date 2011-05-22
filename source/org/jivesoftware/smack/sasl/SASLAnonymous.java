/**
 * $RCSfile$
 * $Revision: $
 * $Date: $
 *
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

/**
 * Implementation of the SASL ANONYMOUS mechanism
 *
 * @author Jay Kline
 */
public class SASLAnonymous extends SASLMechanismType {
    static public class Factory extends SASLMechanismType.Factory {
        public Factory() { super("ANONYMOUS"); }
        public SASLMechanismType create() { return new SASLAnonymous(); }
    }

    public SASLAnonymous() { super("ANONYMOUS"); }

    public byte[] authenticate(String username, String host, CallbackHandler cbh) {
        return null;
    }

    public byte[] authenticate(String username, String host, String password) {
        return null;
    }

    public byte[] challengeReceived(byte[] challenge) {
        return null;
    }


}
