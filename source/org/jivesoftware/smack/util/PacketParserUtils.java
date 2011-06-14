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

package org.jivesoftware.smack.util;

import org.jivesoftware.smack.Connection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smack.provider.IQProvider;
import org.jivesoftware.smack.provider.PacketExtensionProvider;
import org.jivesoftware.smack.provider.ProviderManager;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class that helps to parse packets. Any parsing packets method that must be shared
 * between many clients must be placed in this utility class.
 *
 * @author Gaston Dombiak
 */
public class PacketParserUtils {

    /**
     * Namespace used to store packet properties.
     */
    private static final String PROPERTIES_NAMESPACE =
            "http://www.jivesoftware.com/xmlns/xmpp/properties";

    /**
     * Parses a message packet.
     *
     * @param parser the XML parser, positioned at the start of a message packet.
     * @return a Message packet.
     * @throws XMPPException if an exception occurs while parsing the packet.
     */
    public static Message parseMessage(Element packet) throws XMPPException {
        Message message = new Message();
        String id = packet.getAttribute("id");
        message.setPacketID(id.equals("")? Packet.ID_NOT_AVAILABLE : id);
        message.setTo(packet.getAttribute("to"));
        message.setFrom(packet.getAttribute("from"));
        message.setType(Message.Type.fromString(packet.getAttribute("type")));
        String language = getLanguageAttribute(packet);
        
        // determine message's default language
        String defaultLanguage = null;
        if (!language.equals("")) {
            message.setLanguage(language);
            defaultLanguage = language;
        } 
        else {
            defaultLanguage = Packet.getDefaultLanguage();
        }

        // Parse sub-elements. We include extra logic to make sure the values
        // are only read once. This is because it's possible for the names to appear
        // in arbitrary sub-elements.
        String thread = null;
        Map<String, Object> properties = null;
        for(Element child: XmlUtil.getChildElements(packet)) {
            String elementName = child.getLocalName();
            String namespace = child.getNamespaceURI();
            if (elementName.equals("subject")) {
                String xmlLang = getLanguageAttribute(child);
                if (xmlLang == null) {
                    xmlLang = defaultLanguage;
                }

                String subject = XmlUtil.getTextContent(child);

                if (message.getSubject(xmlLang) == null) {
                    message.addSubject(xmlLang, subject);
                }
            }
            else if (elementName.equals("body")) {
                String xmlLang = getLanguageAttribute(child);
                if (xmlLang == null) {
                    xmlLang = defaultLanguage;
                }

                String body = XmlUtil.getTextContent(child);
                
                if (message.getBody(xmlLang) == null) {
                    message.addBody(xmlLang, body);
                }
            }
            else if (elementName.equals("thread")) {
                if (thread == null) {
                    thread = XmlUtil.getTextContent(child);
                }
            }
            else if (elementName.equals("error")) {
                message.setError(parseError(child));
            }
            else if (elementName.equals("properties") &&
                    namespace.equals(PROPERTIES_NAMESPACE))
            {
                properties = parseProperties(child);
            }
            // Otherwise, it must be a packet extension.
            else {
                message.addExtension(
                PacketParserUtils.parsePacketExtension(elementName, namespace, child));
            }
        }

        message.setThread(thread);
        // Set packet properties.
        if (properties != null) {
            for (String name : properties.keySet()) {
                message.setProperty(name, properties.get(name));
            }
        }
        return message;
    }

    /**
     * Parses a presence packet.
     *
     * @param parser the XML parser, positioned at the start of a presence packet.
     * @return a Presence packet.
     * @throws XMPPException if an exception occurs while parsing the packet.
     */
    public static Presence parsePresence(Element packet) throws XMPPException {
        Presence.Type type = Presence.Type.available;
        String typeString = packet.getAttribute("type");
        if (!typeString.equals("")) {
            try {
                type = Presence.Type.valueOf(typeString);
            }
            catch (IllegalArgumentException iae) {
                System.err.println("Found invalid presence type " + typeString);
            }
        }
        Presence presence = new Presence(type);
        presence.setTo(packet.getAttribute("to"));
        presence.setFrom(packet.getAttribute("from"));
        String id = packet.getAttribute("id");
        presence.setPacketID(id.equals("")? Packet.ID_NOT_AVAILABLE : id);

        String language = getLanguageAttribute(packet);
        if(!language.equals(""))
        	presence.setLanguage(language);

        presence.setPacketID(id.equals("")? Packet.ID_NOT_AVAILABLE : id);

        // Parse sub-elements
        for(Element child: XmlUtil.getChildElements(packet)) {
            String elementName = child.getLocalName();
            String namespace = child.getNamespaceURI();
            if(elementName.equals("status") && namespace.equals("jabber:client")) {
                presence.setStatus(XmlUtil.getTextContent(child));
                continue;
            }
            
            if(elementName.equals("priority") && namespace.equals("jabber:client")) {
                try {
                    int priority = Integer.parseInt(XmlUtil.getTextContent(child));
                    presence.setPriority(priority);
                }
                catch (NumberFormatException nfe) {
                    // Ignore.
                }
                catch (IllegalArgumentException iae) {
                    // Presence priority is out of range so assume priority to be zero
                    presence.setPriority(0);
                }
                
                continue;
            }
            
            if(elementName.equals("show") && namespace.equals("jabber:client")) {
                String modeText = XmlUtil.getTextContent(child);
                try {
                    presence.setMode(Presence.Mode.valueOf(modeText));
                }
                catch (IllegalArgumentException iae) {
                    System.err.println("Found invalid presence mode " + modeText);
                }
                continue;
            }
            if(elementName.equals("error") && namespace.equals("jabber:client")) {
                presence.setError(parseError(child));
                
                continue;
            }

            if(elementName.equals("properties") &&
                    namespace.equals(PROPERTIES_NAMESPACE)) {
                Map<String,Object> properties = parseProperties(child);
                // Set packet properties.
                for (String name : properties.keySet()) {
                    presence.setProperty(name, properties.get(name));
                }
                continue;
            }

            // Otherwise, it must be a packet extension.
            presence.addExtension(PacketParserUtils.parsePacketExtension(elementName, namespace, child));
        }

        return presence;
    }

    /**
     * Parses an IQ packet.
     *
     * @param parser the XML parser, positioned at the start of an IQ packet.
     * @return an IQ object.
     * @throws XMPPException if an exception occurs while parsing the packet.
     */
    public static IQ parseIQ(Element packet, Connection connection) throws XMPPException {
        IQ iqPacket = null;

        String id = packet.getAttribute("id");
        String to = packet.getAttribute("to");
        String from = packet.getAttribute("from");
        IQ.Type type = IQ.Type.fromString(packet.getAttribute("type"));
        XMPPError error = null;

        for(Element child: XmlUtil.getChildElements(packet)) {
            String elementName = child.getLocalName();
            String namespace = child.getNamespaceURI();
            if (elementName.equals("error")) {
                error = PacketParserUtils.parseError(child);
            }
            else if (elementName.equals("query") && namespace.equals("jabber:iq:auth")) {
                iqPacket = parseAuthentication(child);
            }
            else if (elementName.equals("query") && namespace.equals("jabber:iq:roster")) {
                iqPacket = parseRoster(child);
            }
            else if (elementName.equals("query") && namespace.equals("jabber:iq:register")) {
                iqPacket = parseRegistration(child);
            }
            else if (elementName.equals("bind") &&
                    namespace.equals("urn:ietf:params:xml:ns:xmpp-bind")) {
                iqPacket = parseResourceBinding(child);
            }
            // Otherwise, see if there is a registered provider for
            // this element name and namespace.
            else {
                IQProvider provider = ProviderManager.getInstance().getIQProvider(elementName, namespace);
                if (provider != null) {
                    iqPacket = provider.parseIQ(child);
                }
            }
        }

        // Decide what to do when an IQ packet was not understood
        if (iqPacket == null) {
            if (IQ.Type.GET == type || IQ.Type.SET == type ) {
                // If the IQ stanza is of type "get" or "set" containing a child element
                // qualified by a namespace it does not understand, then answer an IQ of
                // type "error" with code 501 ("feature-not-implemented")
                iqPacket = new IQ() {
                    public String getChildElementXML() {
                        return null;
                    }
                };
                iqPacket.setPacketID(id);
                iqPacket.setTo(from);
                iqPacket.setFrom(to);
                iqPacket.setType(IQ.Type.ERROR);
                iqPacket.setError(new XMPPError(XMPPError.Condition.feature_not_implemented));
                connection.sendPacket(iqPacket);
                return null;
            }
            else {
                // If an IQ packet wasn't created above, create an empty IQ packet.
                iqPacket = new IQ() {
                    public String getChildElementXML() {
                        return null;
                    }
                };
            }
        }

        // Set basic values on the iq packet.
        iqPacket.setPacketID(id);
        iqPacket.setTo(to);
        iqPacket.setFrom(from);
        iqPacket.setType(type);
        iqPacket.setError(error);

        return iqPacket;
    }

    private static Authentication parseAuthentication(Element packet) {
        Authentication authentication = new Authentication();
        for(Element child: XmlUtil.getChildElements(packet)) {
            if (child.getLocalName().equals("username"))
                authentication.setUsername(XmlUtil.getTextContent(child));
            else if (child.getLocalName().equals("password"))
                authentication.setPassword(XmlUtil.getTextContent(child));
            else if (child.getLocalName().equals("digest"))
                authentication.setDigest(XmlUtil.getTextContent(child));
            else if (child.getLocalName().equals("resource"))
                authentication.setResource(XmlUtil.getTextContent(child));
        }
        return authentication;
    }

    private static RosterPacket parseRoster(Element packet) {
        RosterPacket roster = new RosterPacket();
        RosterPacket.Item item = null;
        for(Element child: XmlUtil.getChildElements(packet)) {
            if (child.getLocalName().equals("item")) {
                String jid = child.getAttribute("jid");
                String name = child.getAttribute("name");

                // Create packet.
                item = new RosterPacket.Item(jid, name);

                // Set status.
                String ask = child.getAttribute("ask");
                RosterPacket.ItemStatus status = RosterPacket.ItemStatus.fromString(ask);
                item.setItemStatus(status);
                
                // Set type.
                String subscription = child.getAttribute("subscription");
                RosterPacket.ItemType type = RosterPacket.ItemType.valueOf(subscription != null ? subscription : "none");
                item.setItemType(type);
                for(Element child2: XmlUtil.getChildElements(child)) {
                    if (child2.getLocalName().equals("group")) {
                        String groupName = XmlUtil.getTextContent(child2);
                        if (groupName.trim().length() > 0)
                            item.addGroupName(groupName);
                    }
                }
                roster.addRosterItem(item);
            }
        }
        return roster;
    }

     private static Registration parseRegistration(Element packet) throws XMPPException {
        Registration registration = new Registration();
        Map<String, String> fields = null;
        for(Element child: XmlUtil.getChildElements(packet)) {
            // Any element that's in the jabber:iq:register namespace,
            // attempt to parse it if it's in the form <name>value</name>.
            if (child.getNamespaceURI().equals("jabber:iq:register")) {
                String name = child.getLocalName();
                String value = XmlUtil.getTextContent(child);
                if (fields == null) {
                    fields = new HashMap<String, String>();
                }

                // Ignore instructions, but anything else should be added to the map.
                if (!name.equals("instructions")) {
                    fields.put(name, value);
                }
                else {
                    registration.setInstructions(value);
                }
            }
            // Otherwise, it must be a packet extension.
            else {
                registration.addExtension(
                    PacketParserUtils.parsePacketExtension(
                        child.getLocalName(),
                        child.getNamespaceURI(),
                        child));
            }
        }
        registration.setAttributes(fields);
        return registration;
    }

    private static Bind parseResourceBinding(Element packet) {
        Bind bind = new Bind();
        for(Element child: XmlUtil.getChildElements(packet)) {
            if (child.getLocalName().equals("resource")) {
                bind.setResource(XmlUtil.getTextContent(child));
            }
            else if (child.getLocalName().equals("jid")) {
                bind.setJid(XmlUtil.getTextContent(child));
            }
        }

        return bind;
    }

    /**
     * Parse the available SASL mechanisms reported from the server.
     *
     * @param parser the XML parser, positioned at the start of the mechanisms stanza.
     * @return a collection of Stings with the mechanisms included in the mechanisms stanza.
     */
    public static Collection<String> parseMechanisms(Node node) {
        List<String> mechanisms = new ArrayList<String>();
        for(Element child: XmlUtil.getChildElements(node)) {
            String elementName = child.getLocalName();
            if (elementName.equals("mechanism")) {
                mechanisms.add(XmlUtil.getTextContent(child));
            }
        }
        return mechanisms;
    }

    /**
     * Parse a properties sub-packet. If any errors occur while de-serializing Java object
     * properties, an exception will be printed and not thrown since a thrown
     * exception will shut down the entire connection. ClassCastExceptions will occur
     * when both the sender and receiver of the packet don't have identical versions
     * of the same class.
     *
     * @param parser the XML parser, positioned at the start of a properties sub-packet.
     * @return a map of the properties.
     * @throws Exception if an error occurs while parsing the properties.
     */
    public static Map<String, Object> parseProperties(Element packet) {
        Map<String, Object> properties = new HashMap<String, Object>();
        for(Element child: XmlUtil.getChildElements(packet)) {
            if(!child.getLocalName().equals("property"))
                continue;

            // Parse a property
            String name = null;
            String type = null;
            String valueText = null;
            for(Element propertyNode: XmlUtil.getChildElements(child)) {
                String elementName = propertyNode.getLocalName();
                if (elementName.equals("name")) {
                    name = XmlUtil.getTextContent(propertyNode);
                }
                else if (elementName.equals("value")) {
                    type = propertyNode.getAttribute("type");
                    valueText = XmlUtil.getTextContent(propertyNode);
                }
            }

            Object value = null;
            if ("integer".equals(type))
                value = Integer.valueOf(valueText);
            else if ("long".equals(type))
                value = Long.valueOf(valueText);
            else if ("float".equals(type))
                value = Float.valueOf(valueText);
            else if ("double".equals(type))
                value = Double.valueOf(valueText);
            else if ("boolean".equals(type))
                value = Boolean.valueOf(valueText);
            else if ("string".equals(type))
                value = valueText;
            else if ("java-object".equals(type)) {
                try {
                    byte [] bytes = StringUtils.decodeBase64(valueText);
                    ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes));
                    value = in.readObject();
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }

            if (name != null && value != null)
                properties.put(name, value);
        }
        return properties;
    }

    /**
     * Parses stream error packets.
     *
     * @param parser the XML parser.
     * @return an stream error packet.
     */
    public static StreamError parseStreamError(Element packet) {
        for(Element child: XmlUtil.getChildElements(packet)) {
            return new StreamError(packet.getLocalName());
        }
        return null;
    }

    /**
     * Parses error sub-packets.
     *
     * @param packet the XML element.
     * @return an error sub-packet.
     * @throws Exception if an exception occurs while parsing the packet.
     */
    public static XMPPError parseError(Element packet) throws XMPPException {
        final String errorNamespace = "urn:ietf:params:xml:ns:xmpp-stanzas";
        String message = null;
        String condition = null;
        List<PacketExtension> extensions = new ArrayList<PacketExtension>();

        // Parse the error header
        String errorCode = packet.getAttribute("code");
        if(errorCode.equals(""))
            errorCode = "-1";

        boolean done = false;
        // Parse the text and condition tags
        for(Element child: XmlUtil.getChildElements(packet)) {
            String elementName = child.getLocalName();
            String namespace = child.getNamespaceURI();
            if (elementName.equals("text")) {
                message = XmlUtil.getTextContent(child);
            }
            else {
                // Condition tag, it can be xmpp error or an application defined error.
                if (errorNamespace.equals(namespace))
                    condition = elementName;
                else
                    extensions.add(parsePacketExtension(elementName, namespace, child));
            }
        }

        // Parse the error type.
        String type = packet.getAttribute("type");
        if(type.equals(""))
            type = "cancel";

        XMPPError.Type errorType = XMPPError.Type.CANCEL;
        try {
            errorType = XMPPError.Type.valueOf(type.toUpperCase());
        }
        catch (IllegalArgumentException iae) {
            // Print stack trace. We shouldn't be getting an illegal error type.
            iae.printStackTrace();
        }
        return new XMPPError(Integer.parseInt(errorCode), errorType, condition, message, extensions);
    }
    
    /**
     * Parses a packet extension sub-packet.
     *
     * @param elementName the XML element name of the packet extension.
     * @param namespace the XML namespace of the packet extension.
     * @param parser the XML parser, positioned at the starting element of the extension.
     * @return a PacketExtension.
     * @throws Exception if a parsing error occurs.
     * @deprecated Transitional shim.  Use {@link #parsePacketExtension(String, String, Element)}.
     */
    public static PacketExtension parsePacketExtension(String elementName, String namespace, XmlPullParser parser) throws Exception
    {
        Element packet = XmlUtil.ReadNodeFromXmlPull(parser);
        return parsePacketExtension(elementName, namespace, packet);
    }

    /**
     * Parses a packet extension sub-packet.
     *
     * @param elementName the XML element name of the packet extension.
     * @param namespace the XML namespace of the packet extension.
     * @param element the XML element to parse..
     * @return a PacketExtension.
     * @throws Exception if a parsing error occurs.
     */
    public static PacketExtension parsePacketExtension(String elementName, String namespace, Element packet)
    throws XMPPException
    {
        // See if a provider is registered to handle the extension.
        PacketExtensionProvider provider = ProviderManager.getInstance().getExtensionProvider(elementName, namespace);
        if (provider != null)
            return provider.parseExtension(packet);

        // No providers registered, so use a default extension.
        DefaultPacketExtension extension = new DefaultPacketExtension(elementName, namespace);
        for(Element child: XmlUtil.getChildElements(packet)) {
            String name = child.getLocalName();
            extension.setValue(name, XmlUtil.getTextContent(child));
        }
        return extension;
    }

    private static String getLanguageAttribute(Element parser) {
        return parser.getAttributeNS("http://www.w3.org/XML/1998/namespace", "lang").trim();
    }
}
