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

package org.jivesoftware.smack;

import org.jivesoftware.smack.PacketReader.ReaderPacketCallbacks;
import org.jivesoftware.smack.debugger.SmackDebugger;
import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.filter.ReceivedPacketFilter;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.ReceivedPacket;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smack.util.ObservableReader;
import org.jivesoftware.smack.util.ObservableWriter;
import org.jivesoftware.smack.util.ThreadUtil;
import org.jivesoftware.smack.util.XmlUtil;

import org.apache.harmony.javax.security.auth.callback.CallbackHandler;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.Collection;
import java.util.Vector;

import org.w3c.dom.Element;

/**
 * Creates a socket connection to a XMPP server. This is the default connection
 * to a Jabber server and is specified in the XMPP Core (RFC 3920).
 * 
 * @see Connection
 * @author Matt Tucker
 */
public class XMPPConnection extends Connection {
    /**
     * The XMPPStream used for this connection.
     */
    private XMPPStream data_stream = null;

    private String user = null;
    private boolean connected = false;
    /**
     * Flag that indicates if the user is currently authenticated with the server.
     */
    private boolean authenticated = false;

    /**
     * This is false between connectUsingConfiguration calling packetReader.startup()
     * and connection events being fired, during which time no disconnection events
     * will be sent.
     */
    private boolean readyForDisconnection;

    private boolean anonymous = false;

    private boolean suppressConnectionErrors;

    final private PacketWriter packetWriter;
    final private PacketReader packetReader;

    /** The SmackDebugger allows to log and debug XML traffic. */
    protected SmackDebugger debugger = null;

    final ObservableReader.ReadEvent readEvent;
    final ObservableWriter.WriteEvent writeEvent;

    private ReceivedPacket initialFeatures;
    Roster roster = null;

    /** Creates a new XMPP connection with the given {@link ConnectionConfiguration}. */
    public XMPPConnection(ConnectionConfiguration config) {
        super(config);

        readEvent = new ObservableReader.ReadEvent();
        writeEvent = new ObservableWriter.WriteEvent();

        // These won't do anything until we call startup().
        packetReader = new PacketReader(this);
        packetWriter = new PacketWriter(this);

        // If debugging is enabled, we should start the thread that will listen for
        // all packets and then log them.
        if (debugger != null) {
            addPacketListener(debugger.getReaderListener(), null);
            if (debugger.getWriterListener() != null) {
                addPacketSendingListener(debugger.getWriterListener(), null);
            }
        }

        // If debugging is enabled, we open a window and write out all network traffic.
        if (config.isDebuggerEnabled())
            initDebugger();
    }

    public String getConnectionID() {
        if (!isConnected()) {
            return null;
        }
        return data_stream.getConnectionID();
    }

    public String getUser() {
        if (!isAuthenticated()) {
            return null;
        }
        return user;
    }

    /**
     * Log in with the specified username.  SASL will be used if available,
     * falling back on non-SASL.  If username is null, login anonymously.
     */
    private synchronized void performLogin(String username, String password, String resource) throws XMPPException {
        if (!isConnected()) {
            throw new IllegalStateException("Not connected to server.");
        }
        if (authenticated) {
            throw new IllegalStateException("Already logged in to server.");
        }

        SASLAuthentication sasl = new SASLAuthentication(this, initialFeatures);

        String JID = null;
        XMPPException error = null;
        try {
            if (config.isSASLAuthenticationEnabled()) {
                try {
                    // Authenticate using SASL
                    if(password == null && config.getCallbackHandler() != null)
                        JID = sasl.authenticate(username, resource, config.getCallbackHandler());
                    else
                        JID = sasl.authenticate(username, password, resource);
                } catch(XMPPException e) {
                    // On not_authorized, fail.
                    if(e.getXMPPError() != null && e.getXMPPError().getCondition() == "not_authorized")
                        throw e;
                    
                    // If we fail for another reason, continue to try non-SASL.
                    error = e;
                }
            }

            if(JID == null) {
                // Attempt non-SASL authentication.
                NonSASLAuthentication legacyAuth = new NonSASLAuthentication(this);
                if(password == null && config.getCallbackHandler() != null)
                    JID = legacyAuth.authenticate(username, password, resource);
                else
                    JID = legacyAuth.authenticate(username, password, config.getCallbackHandler());
            }
        } catch(XMPPException e) {
            // If we attempted SASL first and it failed, throw the first error and ignore
            // the second non-SASL error.
            if(error == null)
                error = e;

            throw error;
        }

        // Set the user.
        if (JID != null) {
            this.user = JID;
            // Update the serviceName with the one returned by the server
            config.setServiceName(StringUtils.parseServer(JID));
        }
        else {
            this.user = username + "@" + getServiceName();
            if (resource != null) {
                this.user += "/" + resource;
            }
        }

        // Indicate that we're now authenticated.
        authenticated = true;
        anonymous = (username == null);

        // Set presence to online.
        if (config.isSendPresence()) {
            packetWriter.sendPacket(new Presence(Presence.Type.available));
        }

        // If debugging is enabled, change the the debug window title to include the
        // name we are now logged-in as.
        if (debugger != null) {
            debugger.userHasLogged(user);
        }

        // Create the roster if necessary.  The roster will already exist during a
        // reconnection.
        if (this.roster == null)
            this.roster = new Roster(this);
    }

    @Override
    public synchronized void login(String username, String password, String resource) throws XMPPException {
        // Do partial version of nameprep on the username.
        username = username.toLowerCase().trim();

        performLogin(username, password, resource);

        if (config.isRosterLoadedAtLogin()) {
            PacketCollector rosterLoadCollector = roster.reloadCollector();
            rosterLoadCollector.getResult(0);
        }

        // Stores the authentication for future reconnection
        config.setLoginInfo(username, password, resource);
    }

    @Override
    public synchronized void loginAnonymously() throws XMPPException {
        performLogin(null, null, null);
    }

    public Roster getRoster() {
        if (!config.isRosterLoadedAtLogin())
            throw new IllegalStateException("Roster loading is disabled");

        return roster;
    }

    public boolean isConnected() {
        return connected;
    }

    public boolean isSecureConnection() {
        return this.data_stream != null && this.data_stream.isSecureConnection();
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public boolean isAnonymous() {
        return anonymous;
    }

    /**
     * Closes the connection by setting presence to unavailable then closing the stream to
     * the XMPP server. The shutdown logic will be used during a planned disconnection or when
     * dealing with an unexpected disconnection. Unlike {@link #disconnect()} the connection's
     * packet reader, packet writer, and {@link Roster} will not be removed; thus
     * connection's state is kept.
     *
     * @param unavailablePresence the presence packet to send during shutdown.
     */
    protected void shutdown() {
        if (data_stream != null)
            data_stream.disconnect();

        // These will block until the threads are completely shut down.  This should happen
        // immediately, due to calling data_stream.disconnect().
        packetReader.shutdown();
        packetWriter.shutdown();

        // packetReader and packetWriter are gone, so we can safely clear data_stream.
        data_stream = null;

        authenticated = false;
        connected = false;
    }

    public void disconnect(Presence unavailablePresence) {
        boolean wasConnected;
        synchronized(this) {
            wasConnected = connected;
            connected = false;
        }

        // Shutting down will cause I/O exceptions in the reader and writer threads;
        // suppress them.
        suppressConnectionErrors = true;

        // Cleanly close down the connection.
        if (wasConnected)
            data_stream.gracefulDisconnect(unavailablePresence != null? unavailablePresence.toXML():null);

        shutdown();

        if (roster != null) {
            roster.cleanup();
            roster = null;
        }

        suppressConnectionErrors = false;

        // If we're the one that cleared connected, it's our job to notify about the
        // disconnection.
        if(wasConnected)
            notifyConnectionClosed();

        // Clear packet listeners only on final disconnection.  Do this after calling
        // notifyConnectionClosed.  Some listeners unregister themselves (unnecessarily)
        // on disconnection; if we clear listeners before notifyConnectionClosed that'll
        // cause an unnecessary error.
        recvListeners.clear();
        sendListeners.clear();
        collectors.clear();
        interceptors.clear();
    }

    public void sendPacket(Packet packet) {
        if (!isConnected()) {
            throw new IllegalStateException("Not connected to server.");
        }
        if (packet == null) {
            throw new NullPointerException("Packet is null.");
        }
        packetWriter.sendPacket(packet);
    }

    /**
     * Establishes a connection to the XMPP server and performs an automatic login
     * only if the previous connection state was logged (authenticated). It basically
     * creates and maintains a socket connection to the server.<p>
     * <p/>
     * Listeners will be preserved from a previous connection if the reconnection
     * occurs after an abrupt termination.
     *
     * @throws XMPPException if an error occurs while trying to establish the connection.
     */
    ConnectionOpener opener;
    public void connect() throws XMPPException {
        // If we're already connected, or if we've disconnected but havn't yet cleaned
        // up, shut down.
        shutdown();

        opener = new ConnectionOpener(config);

        try {
            data_stream = opener.connect(readEvent, writeEvent);
        } finally {
            opener = null;
        }

        // Connection is successful.
        connected = true;

        readyForDisconnection = false;

        packetReader.startup();
        packetWriter.startup();

        PacketCollector<ReceivedPacket> coll =
            this.createPacketCollector(new ReceivedPacketFilter("features", "http://etherx.jabber.org/streams"),
                ReceivedPacket.class);
        try {
            // Once we set callbacks, PacketCollectors will start receiving messages.  They'll be
            // queued until then, so we won't miss the packet we're looking for if it's received
            // before we get here.
            data_stream.setPacketCallbacks(packetReader.getPacketCallbacks());

            // A <features/> packet has been received.  Read it; we'll need it for login.
            initialFeatures = coll.getResult(0);
        } finally {
            coll.cancel();
        }

        for(Element node: XmlUtil.getChildElements(initialFeatures.getElement())) {
            if(node.getLocalName().equals("register") &&
               node.getNamespaceURI().equals("http://jabber.org/features/iq-register")) {
                getAccountManager().setSupportsAccountCreation(true);
            }
        }

        // Notify listeners that a new connection has been established
        for (ConnectionCreationListener listener: getConnectionCreationListeners()) {
            listener.connectionCreated(XMPPConnection.this);
        }

        // Inform readerThreadException that disconnections are now allowed.
        synchronized(this) {
            readyForDisconnection = true;
            this.notifyAll();
        }
    }

    /**
     * Initialize the {@link #debugger}. You can specify a customized {@link SmackDebugger}
     * by setup the system property <code>smack.debuggerClass</code> to the implementation.
     *
     * @throws IllegalStateException if the reader or writer isn't yet initialized.
     * @throws IllegalArgumentException if the SmackDebugger can't be loaded.
     */
    private void initDebugger() {
        // Detect the debugger class to use.
        // Use try block since we may not have permission to get a system
        // property (for example, when an applet).
        Vector<String> debuggers = new Vector<String>();
        String requestedDebugger = null;
        try {
            requestedDebugger = System.getProperty("smack.debuggerClass");
            debuggers.add(requestedDebugger);
        }
        catch (Throwable t) {
            // Ignore.
        }
        debuggers.add("org.jivesoftware.smackx.debugger.EnhancedDebugger");
        debuggers.add("org.jivesoftware.smackx.debugger.AndroidDebugger");
        debuggers.add("org.jivesoftware.smack.debugger.LiteDebugger");
        for (String debuggerName: debuggers) {
            try {
                Class<?> debuggerClass = Class.forName(debuggerName);

                // Attempt to create an instance of this debugger.
                Constructor<?> constructor = debuggerClass
                        .getConstructor(Connection.class, ObservableWriter.WriteEvent.class, ObservableReader.ReadEvent.class);
                debugger = (SmackDebugger) constructor.newInstance(this, writeEvent, readEvent);
                break;
            }
            catch (Exception e) {
                if(requestedDebugger != null && requestedDebugger.equals(debuggerName))
                    e.printStackTrace();
                continue;
            }
        }
    }

    /*
     * Called when the XMPP stream is reset, usually due to successful
     * authentication.
     */
    public void streamReset() throws XMPPException
    {
        this.data_stream.streamReset();
    }

    public boolean isUsingCompression() {
        return data_stream.isUsingCompression();
    }

    /** Write a list of packets to the stream.  Used by PacketWriter. */
    protected void writePacket(Collection<Packet> packets) throws XMPPException {
        StringBuffer data = new StringBuffer();
        for(Packet packet: packets)
            data.append(packet.toXML());

        data_stream.writePacket(data.toString());
    }

    /**
     * Sends a notification indicating that the connection was closed gracefully.
     */
    protected void notifyConnectionClosed() {
        for (ConnectionListener listener: getConnectionListeners()) {
            try {
                listener.connectionClosed();
            }
            catch (Exception e) {
                // Catch and print any exception so we can recover
                // from a faulty listener and finish the shutdown process
                e.printStackTrace();
            }
        }
    }

    protected void notifyConnectionClosedOnError(Exception e) {
        for (ConnectionListener listener: getConnectionListeners()) {
            try {
                listener.connectionClosedOnError(e);
            }
            catch (Exception e2) {
                // Catch and print any exception so we can recover
                // from a faulty listener
                e2.printStackTrace();
            }
        }
    }

    /**
     * Called by PacketReader when an error occurs after startup() returns successfully.
     *
     * @param error the exception that caused the connection close event.
     */
    protected void readerThreadException(Exception error) {
        // If errors are being suppressed, do nothing.  This happens during shutdown().
        synchronized(this) {
            if(suppressConnectionErrors)
                return;

            // Only send one connection error.
            suppressConnectionErrors = true;
        }

        // Print the stack trace to help catch the problem.  Include the current
        // stack in the output.
        new Exception(error).printStackTrace();

        boolean wasConnected;

        // beginConnection() has returned, so it's guaranteed that
        // connectUsingConfiguration will send out connection or reconnection
        // notifications and set connected = true.  If that hasn't happened
        // yet, wait for it, so we never send a disconnected event before its
        // corresponding connect event.
        synchronized(this) {
            while(!readyForDisconnection) {
                try {
                    this.wait();
                } catch(InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            wasConnected = connected;
            connected = false;
        }

        // Shut down the data stream.  shutdown() must be called to complete shutdown;
        // we're running under the reader thread, which shutdown() shuts down, so we
        // can't do that from here.  It's the responsibility of the user.
        this.data_stream.disconnect();

        // If we're the one that cleared connected, it's our job to notify about the
        // disconnection.
        if(wasConnected)
            notifyConnectionClosedOnError(error);
    }
}
