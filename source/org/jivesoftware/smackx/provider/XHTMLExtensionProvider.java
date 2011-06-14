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

package org.jivesoftware.smackx.provider;

import org.jivesoftware.smack.packet.PacketExtension;
import org.jivesoftware.smack.provider.PacketExtensionProvider;
import org.jivesoftware.smack.util.XmlUtil;
import org.jivesoftware.smackx.packet.XHTMLExtension;
import org.w3c.dom.Element;
import org.xmlpull.v1.XmlPullParser;

/**
 * The XHTMLExtensionProvider parses XHTML packets.
 *
 * @author Gaston Dombiak
 */
public class XHTMLExtensionProvider extends PacketExtensionProvider {

    /**
     * Creates a new XHTMLExtensionProvider.
     * ProviderManager requires that every PacketExtensionProvider has a public, no-argument constructor
     */
    public XHTMLExtensionProvider() {
    }

    /**
     * Parses a XHTMLExtension packet (extension sub-packet).
     *
     * @return a PacketExtension.
     */
    public PacketExtension parseExtension(Element packet) {
        XHTMLExtension xhtmlExtension = new XHTMLExtension();
        for(Element child: XmlUtil.getChildElements(packet)) {
            if (child.getLocalName().equals("body") &&
                child.getNamespaceURI().equals("http://www.w3.org/1999/xhtml")) {
                String content = XmlUtil.elementToString(child);
                xhtmlExtension.addBody(content);
            }
        }

        return xhtmlExtension;
    }

}
