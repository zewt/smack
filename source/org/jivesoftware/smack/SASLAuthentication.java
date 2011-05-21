/**
 * $RCSfile$
 * $Revision: $
 * $Date: $
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

package org.jivesoftware.smack;

import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.filter.PacketIDFilter;
import org.jivesoftware.smack.filter.ReceivedPacketFilter;
import org.jivesoftware.smack.packet.Bind;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.ReceivedPacket;
import org.jivesoftware.smack.packet.Session;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.sasl.*;
import org.jivesoftware.smack.sasl.SASLMechanism.AuthMechanism;
import org.jivesoftware.smack.sasl.SASLMechanism.Response;
import org.jivesoftware.smack.sasl.SASLMechanism.MechanismNotSupported;
import org.jivesoftware.smack.util.Base64;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.harmony.javax.security.auth.callback.CallbackHandler;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

/**
 * <p>This class is responsible authenticating the user using SASL, binding the resource
 * to the connection and establishing a session with the server.</p>
 *
 * <p>Once TLS has been negotiated (i.e. the connection has been secured) it is possible to
 * register with the server, authenticate using Non-SASL or authenticate using SASL. If the
 * server supports SASL then Smack will first try to authenticate using SASL. But if that
 * fails then Non-SASL will be tried.</p>
 *
 * <p>The server may support many SASL mechanisms to use for authenticating. Out of the box
 * Smack provides several SASL mechanisms, but it is possible to register new SASL Mechanisms. Use
 * {@link #registerSASLMechanism(String, Class)} to register a new mechanisms. A registered
 * mechanism wont be used until {@link #supportSASLMechanism(String, int)} is called. By default,
 * the list of supported SASL mechanisms is determined from the {@link SmackConfiguration}. </p>
 *
 * <p>Once the user has been authenticated with SASL, it is necessary to bind a resource for
 * the connection. If no resource is passed in {@link #authenticate(String, String, String)}
 * then the server will assign a resource for the connection. In case a resource is passed
 * then the server will receive the desired resource but may assign a modified resource for
 * the connection.</p>
 *
 * <p>Once a resource has been binded and if the server supports sessions then Smack will establish
 * a session so that instant messaging and presence functionalities may be used.</p>
 *
 * @see org.jivesoftware.smack.sasl.SASLMechanism
 *
 * @author Gaston Dombiak
 * @author Jay Kline
 */
public class SASLAuthentication implements UserAuthentication {

    private static Map<String, Class<? extends SASLMechanism>> implementedMechanisms =
        new HashMap<String, Class<? extends SASLMechanism>>();
    private static List<String> mechanismsPreferences = new ArrayList<String>();

    private Connection connection;
    private Collection<String> serverMechanisms = new ArrayList<String>();
    /**
     * Boolean indicating if SASL negotiation has finished and was successful.
     */
    private boolean saslNegotiated;

    static {

        // Register SASL mechanisms supported by Smack
        registerSASLMechanism("EXTERNAL", SASLExternalMechanism.class);
        registerSASLMechanism("GSSAPI", SASLGSSAPIMechanism.class);
        registerSASLMechanism("DIGEST-MD5", SASLDigestMD5Mechanism.class);
        registerSASLMechanism("CRAM-MD5", SASLCramMD5Mechanism.class);
        registerSASLMechanism("PLAIN", SASLPlainMechanism.class);
        registerSASLMechanism("ANONYMOUS", SASLAnonymous.class);

        supportSASLMechanism("ANONYMOUS", 0);
        supportSASLMechanism("PLAIN", 0);
        supportSASLMechanism("CRAM-MD5", 0);
        supportSASLMechanism("DIGEST-MD5", 0);
        supportSASLMechanism("GSSAPI", 0);

    }

    /**
     * Registers a new SASL mechanism
     *
     * @param name   common name of the SASL mechanism. E.g.: PLAIN, DIGEST-MD5 or KERBEROS_V4.
     * @param mClass a SASLMechanism subclass.
     */
    public static void registerSASLMechanism(String name, Class<? extends SASLMechanism> mClass) {
        implementedMechanisms.put(name, mClass);
    }

    /**
     * Unregisters an existing SASL mechanism. Once the mechanism has been unregistered it won't
     * be possible to authenticate users using the removed SASL mechanism. It also removes the
     * mechanism from the supported list.
     *
     * @param name common name of the SASL mechanism. E.g.: PLAIN, DIGEST-MD5 or KERBEROS_V4.
     */
    public static void unregisterSASLMechanism(String name) {
        implementedMechanisms.remove(name);
        mechanismsPreferences.remove(name);
    }


    /**
     * Registers a new SASL mechanism in the specified preference position. The client will try
     * to authenticate using the most prefered SASL mechanism that is also supported by the server.
     * The SASL mechanism must be registered via {@link #registerSASLMechanism(String, Class)}
     *
     * @param name common name of the SASL mechanism. E.g.: PLAIN, DIGEST-MD5 or KERBEROS_V4.
     */
    public static void supportSASLMechanism(String name) {
        mechanismsPreferences.add(0, name);
    }

    /**
     * Registers a new SASL mechanism in the specified preference position. The client will try
     * to authenticate using the most prefered SASL mechanism that is also supported by the server.
     * Use the <tt>index</tt> parameter to set the level of preference of the new SASL mechanism.
     * A value of 0 means that the mechanism is the most prefered one. The SASL mechanism must be
     * registered via {@link #registerSASLMechanism(String, Class)}
     *
     * @param name common name of the SASL mechanism. E.g.: PLAIN, DIGEST-MD5 or KERBEROS_V4.
     * @param index preference position amongst all the implemented SASL mechanism. Starts with 0.
     */
    public static void supportSASLMechanism(String name, int index) {
        if(index > mechanismsPreferences.size())
            index = mechanismsPreferences.size();
        mechanismsPreferences.add(index, name);
    }

    /**
     * Un-supports an existing SASL mechanism. Once the mechanism has been unregistered it won't
     * be possible to authenticate users using the removed SASL mechanism. Note that the mechanism
     * is still registered, but will just not be used.
     *
     * @param name common name of the SASL mechanism. E.g.: PLAIN, DIGEST-MD5 or KERBEROS_V4.
     */
    public static void unsupportSASLMechanism(String name) {
        mechanismsPreferences.remove(name);
    }

    /**
     * Returns the registerd SASLMechanism classes sorted by the level of preference.
     *
     * @return the registerd SASLMechanism classes sorted by the level of preference.
     */
    public static List<Class<? extends SASLMechanism>> getRegisterSASLMechanisms() {
        List<Class<? extends SASLMechanism>> answer = new ArrayList<Class<? extends SASLMechanism>>();
        for (String mechanismsPreference : mechanismsPreferences) {
            answer.add(implementedMechanisms.get(mechanismsPreference));
        }
        return answer;
    }

    SASLAuthentication(Connection connection, ReceivedPacket features) {
        super();
        this.connection = connection;

        // Record the mechanisms provided in the previous features packet.
        for(Node node: PacketParserUtils.getChildNodes(features.getElement())) {
            if(node.getLocalName().equals("mechanisms")) {
                // The server is reporting available SASL mechanisms. Store this information
                // which will be used later while logging (i.e. authenticating) into
                // the server
                serverMechanisms = PacketParserUtils.parseMechanisms(node);
            }
        }
        this.init();
    }

    /**
     * Returns true if the server offered ANONYMOUS SASL as a way to authenticate users.
     *
     * @return true if the server offered ANONYMOUS SASL as a way to authenticate users.
     */
    public boolean hasAnonymousAuthentication() {
        return serverMechanisms.contains("ANONYMOUS");
    }

    /**
     * Returns true if the server offered SASL authentication besides ANONYMOUS SASL.
     *
     * @return true if the server offered SASL authentication besides ANONYMOUS SASL.
     */
    public boolean hasNonAnonymousAuthentication() {
        return !serverMechanisms.isEmpty() && (serverMechanisms.size() != 1 || !hasAnonymousAuthentication());
    }

    /**
     * Performs SASL authentication of the specified user. If SASL authentication was successful
     * then resource binding and session establishment will be performed. This method will return
     * the full JID provided by the server while binding a resource to the connection.<p>
     *
     * The server may assign a full JID with a username or resource different than the requested
     * by this method.
     *
     * @param username the username that is authenticating with the server.
     * @param resource the desired resource.
     * @param cbh the CallbackHandler used to get information from the user
     * @return the full JID provided by the server while binding a resource to the connection.
     * @throws XMPPException if an error occures while authenticating.
     */
    public String authenticate(String username, String resource, CallbackHandler cbh) 
            throws XMPPException {
        return authenticate(username, cbh, null, resource);
    }

    /**
     * Performs SASL authentication of the specified user. If SASL authentication was successful
     * then resource binding and session establishment will be performed. This method will return
     * the full JID provided by the server while binding a resource to the connection.<p>
     *
     * The server may assign a full JID with a username or resource different than the requested
     * by this method.
     *
     * @param username the username that is authenticating with the server.
     * @param password the password to send to the server.
     * @param resource the desired resource.
     * @return the full JID provided by the server while binding a resource to the connection.
     * @throws XMPPException if an error occures while authenticating.
     */
    public String authenticate(String username, String password, String resource)
            throws XMPPException {
        return authenticate(username, null, password, resource);
    }

    private String authenticateUsingMechanism(String username, CallbackHandler cbh, String password, String resource,
            String mechanism)
            throws XMPPException, SASLMechanism.MechanismNotSupported
    {
        if (saslNegotiated)
            throw new XMPPException("Already authenticated");

        init();

        // A SASL mechanism was found. Authenticate using the selected mechanism and then
        // proceed to bind a resource
        SASLMechanism currentMechanism = createMechanism(implementedMechanisms.get(mechanism));

        // Trigger SASL authentication with the selected mechanism. We use
        // connection.getHost() since GSAPI requires the FQDN of the server, which
        // may not match the XMPP domain.
        PacketFilter filter = new ReceivedPacketFilter(null, "urn:ietf:params:xml:ns:xmpp-sasl");
        PacketCollector coll = connection.createPacketCollector(filter);
        try {
            /* Start authentication. */
            try {
                String authText;
                if(cbh != null)
                    authText = currentMechanism.authenticate(username, connection.getServiceName(), cbh);
                else
                    authText = currentMechanism.authenticate(username, connection.getServiceName(), password);

                // Send the initial packet.
                connection.sendPacket(new AuthMechanism(currentMechanism.getName(), authText));
            } catch(IOException e) {
                e.printStackTrace();
                throw new XMPPException(e);
            }

            while(true) {
                Packet packet = coll.nextResult(SmackConfiguration.getPacketReplyTimeout());
                if(packet == null)
                    throw new XMPPException("SASL authentication timed out", XMPPError.Condition.request_timeout);
                ReceivedPacket receivedPacket = (ReceivedPacket) packet;
                Element element = receivedPacket.getElement();

                if(element.getLocalName().equals("success")) {
                    saslNegotiated = true;
                    break;
                }

                if(element.getLocalName().equals("failure")) {
                    String errorCondition = null;
                    Node firstChild = element.getFirstChild();
                    if(firstChild != null)
                        errorCondition = firstChild.getLocalName();

                    if (errorCondition != null) {
                        throw new XMPPException("SASL authentication " + mechanism + " failed: " + errorCondition,
                                XMPPError.fromErrorCondition(errorCondition));
                    }
                    else {
                        throw new XMPPException("SASL authentication " + mechanism + " failed");
                    }
                }

                if(element.getLocalName().equals("challenge")) {
                    /**
                     * The server is challenging the SASL authentication we just sent. Forward the challenge
                     * to the current SASLMechanism we are using. The SASLMechanism will send a response to
                     * the server. The length of the challenge-response sequence varies according to the
                     * SASLMechanism in use.
                     */
                    try {
                        // Decode the challenge.
                        byte[] challengeData;
                        if(element.getTextContent() != null) // XXX
                            challengeData = Base64.decode(element.getTextContent());
                        else
                            challengeData = new byte[0];

                        // Ask the mechanism for the response.
                        byte[] response = currentMechanism.challengeReceived(challengeData);

                        // Encode the response.
                        Packet responseStanza;
                        if (response == null)
                            responseStanza = new Response();
                        else
                            responseStanza = new Response(Base64.encodeBytes(response,Base64.DONT_BREAK_LINES));

                        // Send the response to the server.
                        connection.sendPacket(responseStanza);
                    } catch(IOException e) {
                        throw new XMPPException(e);
                    }
                }
            }
        } finally {
            connection.removePacketCollector(coll);
        }

        PacketCollector featuresCollector = connection.createPacketCollector(
                new ReceivedPacketFilter("features", "http://etherx.jabber.org/streams"));

        boolean foundBind = false;
        boolean sessionSupported = false;
        try {
            // After successful authentication, the stream must be reset.  This will trigger
            // the next <features/>, which will enable binding.
            connection.streamReset();

            ReceivedPacket features = (ReceivedPacket) featuresCollector.nextResult(SmackConfiguration.getPacketReplyTimeout());
            if(features == null)
                throw new XMPPException("Timed out waiting for post-SASL features");

            // Ensure that we've received the "bind" feature.
            for(Node node: PacketParserUtils.getChildNodes(features.getElement())) {
                if(node.getLocalName().equals("bind") &&
                        node.getNamespaceURI().equals("urn:ietf:params:xml:ns:xmpp-bind"))
                    foundBind = true;
                if(node.getLocalName().equals("session") &&
                        node.getNamespaceURI().equals("urn:ietf:params:xml:ns:xmpp-session"))
                    sessionSupported = true;
            }

            if(!foundBind)
                throw new XMPPException("Authentication successful, but no <bind> feature received");
        } finally {
            featuresCollector.cancel();
        }

        // Bind a resource for this connection.
        String JID = bindResourceAndEstablishSession(resource);

        // If sessions are supported, establish a session.  XXX: This is obsolete
        // and removed in RFC6121.  See if this can be removed.
        if(sessionSupported)
            establishSession();

        return JID;
    }

    private String authenticate(String username, CallbackHandler cbh, String password, String resource)
            throws XMPPException
    {
        if(cbh != null && password != null)
            throw new IllegalArgumentException();

        // Try each available SASL mechanism in order of preference until we try one
        // that works, or the server closes the connection.
        XMPPException error = null;
        for (String mechanism: mechanismsPreferences) {
            if (!implementedMechanisms.containsKey(mechanism) || !serverMechanisms.contains(mechanism))
                continue;

            try {
                return authenticateUsingMechanism(username, cbh, password, resource, mechanism);
            }
            catch (SASLMechanism.MechanismNotSupported e) {
                // The mechanism isn't supported by the local system.  Keep looking.
            }
            catch (XMPPException e) {
                // The mechanism was supported, but failed.  If it failed due to a timeout,
                // stop trying and rethrow the exception.
                XMPPError xmppError = e.getXMPPError();
                if(xmppError != null && xmppError.getCondition().equals("request-timeout"))
                    throw e;

                // We've found a shared mechanism, and it failed to log in.  Stop looking.
                // We could keep trying other mechanisms, which the spec allows (but doesn't
                // require), but unless it's to work around buggy servers there seems to be
                // no point in doing so.  It would lower security by making us attempt PLAIN
                // when we don't need to, and it would cause password callbacks to be run
                // repeatedly.
                error = e;
                break;
            }
        }

        // If any supported SASL methods were attempted and failed, rethrow the error.
        if(error != null)
            throw error;

        throw new XMPPException("No supported SASL methods found");
    }

    /**
     * Performs ANONYMOUS SASL authentication. If SASL authentication was successful
     * then resource binding and session establishment will be performed. This method will return
     * the full JID provided by the server while binding a resource to the connection.<p>
     *
     * The server will assign a full JID with a randomly generated resource and possibly with
     * no username.
     *
     * @return the full JID provided by the server while binding a resource to the connection.
     * @throws XMPPException if an error occures while authenticating.
     */
    public String authenticateAnonymously() throws XMPPException {
        try {
            return authenticateUsingMechanism("", null, "", "", "ANONYMOUS");
        } catch (MechanismNotSupported e) {
            // Anonymous authentication never throws MechanismNotSupported.
            throw new RuntimeException(e);
        }
    }

    SASLMechanism createMechanism(Class<? extends SASLMechanism> mechanismClass) {
        try {
            Constructor<? extends SASLMechanism> constructor = mechanismClass.getConstructor();
            return constructor.newInstance();
        } catch (InvocationTargetException e) {
            // If the constructor throws an exception, it's an unexpected failure; don't
            // mask it.
            Throwable e2 = e.getCause();
            throw new RuntimeException("Error instantiating mechanism", e2);
        } catch (Exception e) {
            return null;
        }
    }

    private String bindResourceAndEstablishSession(String resource) throws XMPPException {
        Bind bindResource = new Bind();
        bindResource.setResource(resource);

        PacketCollector collector = connection
                .createPacketCollector(new PacketIDFilter(bindResource.getPacketID()));
        // Send the packet
        connection.sendPacket(bindResource);
        // Wait up to a certain number of seconds for a response from the server.
        Bind response = (Bind) collector.nextResult(SmackConfiguration.getPacketReplyTimeout());
        collector.cancel();
        if (response == null) {
            throw new XMPPException("No response from the server.");
        }
        // If the server replied with an error, throw an exception.
        else if (response.getType() == IQ.Type.ERROR) {
            throw new XMPPException(response.getError());
        }
        return response.getJid();
    }

    private void establishSession() throws XMPPException {
        Session session = new Session();
        PacketCollector collector = connection.createPacketCollector(new PacketIDFilter(session.getPacketID()));
        // Send the packet
        connection.sendPacket(session);
        // Wait up to a certain number of seconds for a response from the server.
        IQ ack = (IQ) collector.nextResult(SmackConfiguration.getPacketReplyTimeout());
        collector.cancel();
        if (ack == null) {
            throw new XMPPException("No response from the server.");
        }
        // If the server replied with an error, throw an exception.
        else if (ack.getType() == IQ.Type.ERROR) {
            throw new XMPPException(ack.getError());
        }
    }

    /**
     * Returns true if the user was able to authenticate with the server usins SASL.
     *
     * @return true if the user was able to authenticate with the server usins SASL.
     */
    public boolean isAuthenticated() {
        return saslNegotiated;
    }
    
    /**
     * Initializes the internal state in order to be able to be reused. The authentication
     * is used by the connection at the first login and then reused after the connection
     * is disconnected and then reconnected.
     */
    protected void init() {
        saslNegotiated = false;
    }
}