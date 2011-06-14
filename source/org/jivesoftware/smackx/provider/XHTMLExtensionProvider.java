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
     * @param parser the XML parser, positioned at the starting element of the extension.
     * @return a PacketExtension.
     * @throws Exception if a parsing error occurs.
     */
    protected PacketExtension parseExtension(XmlPullParser parser)
        throws Exception {
        XHTMLExtension xhtmlExtension = new XHTMLExtension();
        int startDepth = parser.getDepth();
        while (true) {
            int eventType = parser.next();
            if (eventType == XmlPullParser.START_TAG) {
                if (parser.getName().equals("body") &&
                    parser.getNamespace().equals("http://www.w3.org/1999/xhtml")) {
                    String content = XmlUtil.parserNodeToString(parser);
                    xhtmlExtension.addBody(content);
                    continue;
                }

                // Ignore any unrecognized tags.  Read until we receive the END_TAG at our
                // current level.
                int currentLevel = parser.getDepth();
                do {
                    eventType = parser.next();
                    if(eventType == XmlPullParser.END_DOCUMENT)
                        break;
                } while(eventType != XmlPullParser.END_TAG || parser.getDepth() > currentLevel);
            } else if (eventType == XmlPullParser.END_TAG) {
                if (parser.getName().equals(xhtmlExtension.getElementName())
                        && parser.getDepth() <= startDepth) {
                    break;
                }
            }
        }

        return xhtmlExtension;
    }

}
