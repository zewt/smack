/**
 * $RCSfile$
 * $Revision$
 * $Date$
 *
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

package org.jivesoftware.smack.provider;

import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.PacketExtension;
import org.jivesoftware.smack.util.XmlPullParserDom;
import org.jivesoftware.smack.util.XmlUtil;
import org.w3c.dom.Element;
import org.xmlpull.v1.XmlPullParser;

/**
 * An interface for parsing custom packets extensions. Each PacketExtensionProvider must
 * be registered with the ProviderManager class for it to be used. Every implementation
 * of this interface <b>must</b> have a public, no-argument constructor.
 *
 * @author Matt Tucker
 */
public abstract class PacketExtensionProvider {

    /**
     * Parse an extension sub-packet and create a PacketExtension instance. At
     * the beginning of the method call, the xml parser will be positioned on the
     * opening element of the packet extension. At the end of the method call, the
     * parser <b>must</b> be positioned on the closing element of the packet extension.
     *
     * @param parser an XML parser.
     * @return a new IQ instance.
     * @throws java.lang.Exception if an error occurs parsing the XML.
     */
    protected PacketExtension parseExtension(XmlPullParser parser) throws Exception {
        throw new RuntimeException("parseIQ(Element) threw UseXmlPullParser, but parseIQ(XmlPullParser) is not implement");
    }

    /**
     * Parse an extension sub-packet and create a PacketExtension instance.
     * <p>
     * Transitionally, this is optional.  The default implementation converts to an
     * XmlPullParser and calls {@link #parseExtension(XmlPullParser)}.
     * 
     * @param parser the XML element.
     */
    public PacketExtension parseExtension(Element packet) throws XMPPException {
        try {
            XmlPullParser parser = new XmlPullParserDom(packet, true);
            if(parser.getEventType() != XmlPullParserDom.START_DOCUMENT)
                throw new XMPPException("Invalid XmlPullParser state");
            parser.next();
            if(parser.getEventType() != XmlPullParserDom.START_TAG)
                throw new XMPPException("Invalid XmlPullParser state");

            return parseExtension(parser);
        } catch(Exception e2) {
            throw new XMPPException(e2);
        }
    }
}
