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

import java.util.Map;
import org.apache.harmony.javax.security.sasl.Sasl;

/**
 * Implementation of the SASL GSSAPI mechanism
 *
 * @author Jay Kline
 */
public class SASLGSSAPIMechanism extends SASLMechanism {
    static public class Factory extends SASLMechanism.Factory {
        public Factory() { super("GSSAPI"); }
        public SASLMechanism create() { return new SASLGSSAPIMechanism(); }
    }

    public SASLGSSAPIMechanism() {
        super("GSSAPI");

        System.setProperty("javax.security.auth.useSubjectCredsOnly","false");
        System.setProperty("java.security.auth.login.config","gss.conf");
    }

    protected void applyProperties(Map<String,String> props) {
        props.put(Sasl.SERVER_AUTH,"TRUE");
    }
}
