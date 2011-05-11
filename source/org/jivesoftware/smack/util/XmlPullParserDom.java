/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.jivesoftware.smack.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import org.w3c.dom.Attr;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Text;
import org.w3c.dom.Node;
import org.w3c.dom.Element;

/**
 * Existing code is written to use XmlPullParser.  It should probably be rewritten
 * to use a simpler DOM interface, since pull parsing is only needed for parsing
 * the low-level stream, and it's much simpler when parsing BOSH.  For now, this
 * adapter takes a DOM element and exposes it as an XmlPullParser.
 */
public class XmlPullParserDom implements XmlPullParser {
    private static final String NOT_A_START_TAG = "This is not a start tag.";

    final boolean processNamespaces;

    private Event currentEvent = null;
    private Event last = currentEvent;

    public XmlPullParserDom(Element root, boolean processNamespaces)
    {
        this.processNamespaces = processNamespaces;
        recursivelyAddElement(root, processNamespaces, 0);        
    }

    public void setFeature(String name, boolean state)
            throws XmlPullParserException {
        throw new XmlPullParserException("Unknown feature " + name);
    }

    public boolean getFeature(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Null feature name");
        }

        // We always support namespaces, but no other features.
        return name.equals(FEATURE_PROCESS_NAMESPACES) && processNamespaces;
    }

    public void setProperty(String name, Object value)
            throws XmlPullParserException {
        if (name == null) {
            // Required by API.
            throw new IllegalArgumentException("Null feature name");
        }

        // We don't support any properties.
        throw new XmlPullParserException("Properties aren't supported.");
    }

    public Object getProperty(String name) {
        return null;
    }

    public void setInput(Reader in) throws XmlPullParserException {
        throw new XmlPullParserException("setInput not supported");
    }

    public void setInput(InputStream in, String encodingName) throws XmlPullParserException {
        throw new XmlPullParserException("setInput not supported");
    }

    public String getInputEncoding() {
        return "UTF-16";
    }

    public void defineEntityReplacementText(String entityName,
            String replacementText) throws XmlPullParserException {
        throw new UnsupportedOperationException();
    }

    public int getNamespaceCount(int depth) throws XmlPullParserException {
        return 0;
    }

    /* Retrieving an accumulated list of defiend namespaces isn't supported,
     * since it's not needed.  Retrieving the namespace for elements and
     * attributes is supported normally. */
    public String getNamespacePrefix(int pos) throws XmlPullParserException {
        return null;
    }

    public String getNamespaceUri(int pos) throws XmlPullParserException {
        return null;
    }

    public String getNamespace(String prefix) {
        return null;
    }

    public String getPositionDescription() {
        return "line " + getLineNumber() + ", column " + getColumnNumber();
    }

    /**
     * Not supported.
     *
     * @return {@literal -1} always
     */
    public int getLineNumber() {
        return -1;
    }

    /**
     * Not supported.
     *
     * @return {@literal -1} always
     */
    public int getColumnNumber() {
        return -1;
    }

    public boolean isWhitespace() throws XmlPullParserException {
        if (getEventType() != TEXT) {
            throw new XmlPullParserException("Not on text.");
        }

        String text = getText();

        if (text.length() == 0) {
            return true;
        }

        int length = text.length();
        for (int i = 0; i < length; i++) {
            if (!Character.isWhitespace(text.charAt(i))) {
                return false;
            }
        }

        return true;
    }

    public String getText() {
        final StringBuilder builder = currentEvent.getText();
        return builder == null ? null : builder.toString();
    }

    public char[] getTextCharacters(int[] holderForStartAndLength) {
        final StringBuilder builder = currentEvent.getText();

        final int length = builder.length();
        char[] characters = new char[length];
        builder.getChars(0, length, characters, 0);

        holderForStartAndLength[0] = 0;
        holderForStartAndLength[1] = length;

        return characters;
    }

    public String getNamespace() {
        return currentEvent.getNamespace();
    }

    public String getName() {
        return currentEvent.getName();
    }

    /**
     * Not supported.
     *
     * @throws UnsupportedOperationException always
     */
    public String getPrefix() {
        throw new UnsupportedOperationException();
    }

    public boolean isEmptyElementTag() throws XmlPullParserException {
        return isCurrentElementEmpty();
    }

    public int getAttributeCount() {
        return currentEvent.getAttributeCount();
    }

    public String getAttributeNamespace(int index) {
        return currentEvent.getAttributeNamespace(index);
    }

    public String getAttributeName(int index) {
        return currentEvent.getAttributeName(index);
    }

    /**
     * Not supported.
     *
     * @throws UnsupportedOperationException always
     */
    public String getAttributePrefix(int index) {
        throw new UnsupportedOperationException();
    }

    public String getAttributeType(int index) {
        return "CDATA";
    }

    public boolean isAttributeDefault(int index) {
        return false;
    }

    public String getAttributeValue(int index) {
        return currentEvent.getAttributeValue(index);
    }

    public String getAttributeValue(String namespace, String name) {
        // To XmlPullParser, no namespace is "".  However, attributes is a DOM object,
        // where null means no namespace.
        if(namespace == "")
            namespace = null;
        
        return currentEvent.getAttributeValue(namespace, name);
    }

    public int getEventType() throws XmlPullParserException {
        return currentEvent.getType();
    }

    public int next() throws XmlPullParserException, IOException {
        return dequeue();
    }

    /**
     * Not supported.
     *
     * @throws UnsupportedOperationException always
     */
    public int nextToken() throws XmlPullParserException, IOException {
        throw new UnsupportedOperationException();
    }

    public void require(int type, String namespace, String name)
            throws XmlPullParserException, IOException {
        if(namespace == "")
            namespace = null;

        if (type != getEventType()
                || (namespace != null && !namespace.equals(getNamespace()))
                || (name != null && !name.equals(getName()))) {
            throw new XmlPullParserException("expected "
                    + TYPES[type] + getPositionDescription());
        }
    }

    public String nextText() throws XmlPullParserException, IOException {
        if (currentEvent.getType() != START_TAG)
            throw new XmlPullParserException("Not on start tag.");

        int next = dequeue();
        switch (next) {
            case TEXT: return getText();
            case END_TAG: return "";
            default: throw new XmlPullParserException(
                "Unexpected event type: " + TYPES[next]);
        }
    }

    public int nextTag() throws XmlPullParserException, IOException {
        int eventType = next();
        if (eventType == TEXT && isWhitespace()) {
            eventType = next();
        }
        if (eventType != START_TAG && eventType != END_TAG) {
            throw new XmlPullParserException(
                "Expected start or end tag", this, null);
        }
        return eventType;
    }

    /**
     * Base class for events. Implements event chaining and defines event API
     * along with common implementations which can be overridden.
     */
    static abstract class Event {

        /** Element depth at the time of this event. */
        final int depth;

        /** Next event in the queue. */
        Event next = null;

        Event(int depth) {
            this.depth = depth;
        }

        void setNext(Event next) {
            this.next = next;
        }

        Event getNext() {
            return next;
        }

        StringBuilder getText() {
            return null;
        }

        String getNamespace() {
            return null;
        }

        String getName() {
            return null;
        }

        int getAttributeCount() {
            return -1;
        }

        String getAttributeNamespace(int index) {
            throw new IndexOutOfBoundsException(NOT_A_START_TAG);
        }

        String getAttributeName(int index) {
            throw new IndexOutOfBoundsException(NOT_A_START_TAG);
        }

        String getAttributeValue(int index) {
            throw new IndexOutOfBoundsException(NOT_A_START_TAG);
        }

        abstract int getType();

        String getAttributeValue(String namespace, String name) {
            throw new IndexOutOfBoundsException(NOT_A_START_TAG);
        }

        public int getDepth() {
            return this.depth;
        }
    }

    static class StartDocumentEvent extends Event {

        public StartDocumentEvent() {
            super(0);
        }

        @Override
        int getType() {
            return START_DOCUMENT;
        }
    }

    static class StartTagEvent extends Event {

        final String name;
        final String namespace;
        final NamedNodeMap attributes;
        final boolean processNamespaces;

        StartTagEvent(String namespace,
                String name,
                NamedNodeMap attributes,
                int depth,
                boolean processNamespaces) {
            super(depth);
            this.namespace = namespace;
            this.name = name;
            this.attributes = attributes;
            this.processNamespaces = processNamespaces;
        }

        @Override
        String getNamespace() {
            return namespace;
        }

        @Override
        String getName() {
            return name;
        }

        @Override
        int getAttributeCount() {
            if(getType() != START_TAG)
                throw new IndexOutOfBoundsException();

            return attributes.getLength();
        }

        @Override
        String getAttributeNamespace(int index) {
            if(getType() != START_TAG)
                throw new IndexOutOfBoundsException();

            Attr attr = (Attr) attributes.item(index);
            if(attr == null)
                throw new IndexOutOfBoundsException(); 
            return attr.getNamespaceURI();
        }

        @Override
        String getAttributeName(int index) {
            if(getType() != START_TAG)
                throw new IndexOutOfBoundsException();

            Attr attr = (Attr) attributes.item(index);
            if(attr == null)
                throw new IndexOutOfBoundsException(); 
            
            return processNamespaces ? attr.getLocalName()
                    : attr.getName();
        }

        @Override
        String getAttributeValue(int index) {
            if(getType() != START_TAG)
                throw new IndexOutOfBoundsException();

            Attr attr = (Attr) attributes.item(index);
            if(attr == null)
                throw new IndexOutOfBoundsException(); 
            return attr.getValue();
        }

        @Override
        String getAttributeValue(String namespace, String name) {
            if(getType() != START_TAG)
                throw new IndexOutOfBoundsException();

            Attr attr = (Attr) attributes.getNamedItemNS(namespace, name);
            if(attr == null)
                return null;
            return attr.getValue();
        }

        @Override
        int getType() {
            return START_TAG;
        }
    }

    static class EndTagEvent extends Event {

        final String namespace;
        final String localName;

        EndTagEvent(String namespace, String localName, int depth) {
            super(depth);
            this.namespace = namespace;
            this.localName = localName;
        }

        @Override
        String getName() {
            return this.localName;
        }

        @Override
        String getNamespace() {
            return this.namespace;
        }

        @Override
        int getType() {
            return END_TAG;
        }
    }

    static class TextEvent extends Event {

        final StringBuilder builder;

        public TextEvent(int depth) {
            super(depth);
            this.builder = new StringBuilder();
        }

        @Override
        int getType() {
            return TEXT;
        }

        @Override
        StringBuilder getText() {
            return this.builder;
        }

        void append(String text) {
            builder.append(text);
        }
    }

    static class EndDocumentEvent extends Event {

        EndDocumentEvent() {
            super(0);
        }

        @Override
        Event getNext() {
            throw new IllegalStateException("End of document.");
        }

        @Override
        void setNext(Event next) {
            throw new IllegalStateException("End of document.");
        }

        @Override
        int getType() {
            return END_DOCUMENT;
        }
    }

    /**
     * Adds an event.
     */
    private void add(Event event) {
        if(last != null)
            last.setNext(event);
        last = event;
    }

    /**
     * Moves to the next event in the queue.
     *
     * @return type of next event
     */
    int dequeue() {
        Event next = currentEvent.getNext();

        currentEvent.next = null;
        currentEvent = next;

        return currentEvent.getType();
    }

    public int getDepth() {
        return currentEvent.getDepth();
    }

    void recursivelyAddElement(Element currentNode, boolean processNamespaces, int depth) {
        if(depth == 0)
        {
            add(new StartDocumentEvent());
            currentEvent = last;
        }

        add(new StartTagEvent(currentNode.getNamespaceURI(), currentNode.getLocalName(), currentNode.getAttributes(), depth,
                processNamespaces));

        TextEvent textEvent = null;
        for (Node child = currentNode.getFirstChild(); child != null; child = child.getNextSibling())
        {
            if(child instanceof Text)
            {
                // Ignore empty strings.
                Text text = (Text) child;
                if (text.getLength() == 0)
                    continue;

                // Start a new text event if necessary.
                if (textEvent == null) {
                    textEvent = new TextEvent(depth);
                    add(textEvent);
                }

                // Append to an existing text event.
                textEvent.append(text.getData());
                continue;
            }

            textEvent = null;
            
            if(child instanceof Element)
                recursivelyAddElement((Element) child, processNamespaces, depth + 1);
        }

        add(new EndTagEvent(currentNode.getNamespaceURI(), currentNode.getLocalName(), depth));
        
        if(depth == 0)
            add(new EndDocumentEvent());
    }

    /**
     * Returns true if we're on a start element and the next event is
     * its corresponding end element.
     *
     * @throws XmlPullParserException if we aren't on a start element
     */
    boolean isCurrentElementEmpty() throws XmlPullParserException {
        if (currentEvent.getType() != START_TAG) {
            throw new XmlPullParserException(NOT_A_START_TAG);
        }

        Event next = currentEvent.getNext();
        return next.getType() == END_TAG;
    }
}
