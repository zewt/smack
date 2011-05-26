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

package org.jivesoftware.smack.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class XmlUtil {
    /**
     * Parse an XML document, and return the resulting {@link Document}.
     *
     * @throws SAXException if XML parsing fails
     * @throws IOException if reading from stream fails
     */
    public static Document parseXML(InputSource stream) throws SAXException, IOException {
        DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
        dbfac.setNamespaceAware(true);
        DocumentBuilder docBuilder;
        try {
            docBuilder = dbfac.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }

        return docBuilder.parse(stream);
    }

    /**
     * Parse an XML document, and return the resulting root {@link Node}.
     *
     * @throws SAXException if XML parsing fails
     * @throws IOException if reading from stream fails
     */
    public static Element getXMLRootNode(InputSource stream) throws SAXException, IOException {
        Document doc = parseXML(stream);
        for(Element data: XmlUtil.getChildElements(doc))
            return data;

        throw new RuntimeException("Document had no root node");
    }

    /**
     * Return an iterable Collection<Node> of the child Elements of the specified
     * node.
     *
     * @param parent The parent node.
     * @return A collection of child nodes.
     */
    public static Collection<Element> getChildElements(Node node) {
        NodeList children = node.getChildNodes();
        ArrayList<Element> result = new ArrayList<Element>(children.getLength());
        for(int i = 0; i < children.getLength(); ++i) {
            Node child = children.item(i);
            if(!(child instanceof Element))
                continue;
            result.add((Element) child);
        }
        return result;
    }

    /**
     * Implement Node.getTextContent(), which isn't available in DOM Level 2.
     */
    public static String getTextContent(Node node) {
        String result = "";
        if(node instanceof Text)
            result = ((Text) node).getData();

        for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling())
            result += getTextContent(child);

        return result;
    }
};
