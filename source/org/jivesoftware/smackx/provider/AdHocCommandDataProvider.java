/**
 * $RCSfile$
 * $Revision: $
 * $Date: $
 *
 * Copyright 2005-2007 Jive Software.
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

import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.PacketExtension;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.provider.IQProvider;
import org.jivesoftware.smack.provider.PacketExtensionProvider;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smack.util.XmlUtil;
import org.jivesoftware.smackx.commands.AdHocCommand;
import org.jivesoftware.smackx.commands.AdHocCommand.Action;
import org.jivesoftware.smackx.commands.AdHocCommandNote;
import org.jivesoftware.smackx.packet.AdHocCommandData;
import org.jivesoftware.smackx.packet.DataForm;
import org.w3c.dom.Element;
import org.xmlpull.v1.XmlPullParser;

/**
 * The AdHocCommandDataProvider parses AdHocCommandData packets.
 * 
 * @author Gabriel Guardincerri
 */
public class AdHocCommandDataProvider extends IQProvider {

    public IQ parseIQ(Element packet) throws XMPPException {
        AdHocCommandData adHocCommandData = new AdHocCommandData();
        DataFormProvider dataFormProvider = new DataFormProvider();

        adHocCommandData.setSessionID(packet.getAttribute("sessionid"));
        adHocCommandData.setNode(packet.getAttribute("node"));

        // Status
        String status = packet.getAttribute("status");
        if (AdHocCommand.Status.executing.toString().equalsIgnoreCase(status)) {
            adHocCommandData.setStatus(AdHocCommand.Status.executing);
        }
        else if (AdHocCommand.Status.completed.toString().equalsIgnoreCase(status)) {
            adHocCommandData.setStatus(AdHocCommand.Status.completed);
        }
        else if (AdHocCommand.Status.canceled.toString().equalsIgnoreCase(status)) {
            adHocCommandData.setStatus(AdHocCommand.Status.canceled);
        }

        // Action
        String action = packet.getAttribute("action");
        if (action != null) {
            Action realAction = AdHocCommand.Action.valueOf(action);
            if (realAction == null || realAction.equals(Action.unknown)) {
                adHocCommandData.setAction(Action.unknown);
            }
            else {
                adHocCommandData.setAction(realAction);
            }
        }
        for(Element child: XmlUtil.getChildElements(packet)) {
            String elementName = child.getLocalName();
            String namespace = child.getNamespaceURI();
                if (elementName.equals("actions")) {
                    String execute = child.getAttribute("execute");
                    if (!execute.equals(""))
                        adHocCommandData.setExecuteAction(AdHocCommand.Action.valueOf(execute));
                }
                else if (elementName.equals("next")) {
                    adHocCommandData.addAction(AdHocCommand.Action.next);
                }
                else if (elementName.equals("complete")) {
                    adHocCommandData.addAction(AdHocCommand.Action.complete);
                }
                else if (elementName.equals("prev")) {
                    adHocCommandData.addAction(AdHocCommand.Action.prev);
                }
                else if (elementName.equals("x") && namespace.equals("jabber:x:data")) {
                    adHocCommandData.setForm((DataForm) dataFormProvider.parseExtension(packet));
                }
                else if (elementName.equals("note")) {
                    AdHocCommandNote.Type type = AdHocCommandNote.Type.valueOf(
                            child.getAttribute("type"));
                    String value = XmlUtil.getTextContent(child);
                    adHocCommandData.addNote(new AdHocCommandNote(type, value));
                }
                else if (elementName.equals("error")) {
                    XMPPError error = PacketParserUtils.parseError(child);
                    adHocCommandData.setError(error);
                }
        }
        return adHocCommandData;
    }

    public static class BadActionError extends PacketExtensionProvider {
        public PacketExtension parseExtension(XmlPullParser parser) throws Exception {
            return new AdHocCommandData.SpecificError(AdHocCommand.SpecificErrorCondition.badAction);
        }
    }

    public static class MalformedActionError extends PacketExtensionProvider {
        public PacketExtension parseExtension(XmlPullParser parser) throws Exception {
            return new AdHocCommandData.SpecificError(AdHocCommand.SpecificErrorCondition.malformedAction);
        }
    }

    public static class BadLocaleError extends PacketExtensionProvider {
        public PacketExtension parseExtension(XmlPullParser parser) throws Exception {
            return new AdHocCommandData.SpecificError(AdHocCommand.SpecificErrorCondition.badLocale);
        }
    }

    public static class BadPayloadError extends PacketExtensionProvider {
        public PacketExtension parseExtension(XmlPullParser parser) throws Exception {
            return new AdHocCommandData.SpecificError(AdHocCommand.SpecificErrorCondition.badPayload);
        }
    }

    public static class BadSessionIDError extends PacketExtensionProvider {
        public PacketExtension parseExtension(XmlPullParser parser) throws Exception {
            return new AdHocCommandData.SpecificError(AdHocCommand.SpecificErrorCondition.badSessionid);
        }
    }

    public static class SessionExpiredError extends PacketExtensionProvider {
        public PacketExtension parseExtension(XmlPullParser parser) throws Exception {
            return new AdHocCommandData.SpecificError(AdHocCommand.SpecificErrorCondition.sessionExpired);
        }
    }
}
