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

    /**
     * Flag that indicates if the user was authenticated with the server when the connection
     * to the server was closed (abruptly or not).
     */
    private boolean wasAuthenticated = false;
    private boolean anonymous = false;

    /** True if we've yet to connect to a server. */
    private boolean isFirstInitialization = true;

    private boolean suppressConnectionErrors;

    private PacketWriter packetWriter;
    private PacketReader packetReader;

    /** The SmackDebugger allows to log and debug XML traffic. */
    protected SmackDebugger debugger = null;

    final ObservableReader.ReadEvent readEvent;
    final ObservableWriter.WriteEvent writeEvent;

    private ReceivedPacket initialFeatures;
    Roster roster = null;

    /**
     * Creates a new connection to the specified XMPP server. A DNS SRV lookup will be
     * performed to determine the IP address and port corresponding to the
     * service name; if that lookup fails, it's assumed that server resides at
     * <tt>serviceName</tt> with the default port of 5222. Encrypted connections (TLS)
     * will be used if available, stream compression is disabled, and standard SASL
     * mechanisms will be used for authentication.<p>
     * <p/>
     * This is the simplest constructor for connecting to an XMPP server. Alternatively,
     * you can get fine-grained control over connection settings using the
     * {@link #XMPPConnection(ConnectionConfiguration)} constructor.<p>
     * <p/>
     * Note that XMPPConnection constructors do not establish a connection to the server
     * and you must call {@link #connect()}.<p>
     * <p/>
     * The CallbackHandler will only be used if the connection requires the client provide
     * an SSL certificate to the server. The CallbackHandler must handle the PasswordCallback
     * to prompt for a password to unlock the keystore containing the SSL certificate.
     *
     * @param serviceName the name of the XMPP server to connect to; e.g. <tt>example.com</tt>.
     * @param callbackHandler the CallbackHandler used to prompt for the password to the keystore.
     */
    public XMPPConnection(String serviceName, CallbackHandler callbackHandler) {
        this(new ConnectionConfiguration(serviceName), callbackHandler, serviceName);
    }

    /**
     * Creates a new XMPP connection in the same way {@link #XMPPConnection(String,CallbackHandler)} does, but
     * with no callback handler for password prompting of the keystore.  This will work
     * in most cases, provided the client is not required to provide a certificate to 
     * the server.
     *
     * @param serviceName the name of the XMPP server to connect to; e.g. <tt>example.com</tt>.
     */
    public XMPPConnection(String serviceName) {
        this(new ConnectionConfiguration(serviceName), null, serviceName);
    }

    /**
     * Creates a new XMPP connection in the same way {@link #XMPPConnection(ConnectionConfiguration,CallbackHandler)} does, but
     * with no callback handler for password prompting of the keystore.  This will work
     * in most cases, provided the client is not required to provide a certificate to 
     * the server.
     *
     *
     * @param config the connection configuration.
     */
    public XMPPConnection(ConnectionConfiguration config) {
        this(config, null, null);
    }

    /**
     * Creates a new XMPP connection using the specified connection configuration.<p>
     * <p/>
     * Manually specifying connection configuration information is suitable for
     * advanced users of the API. In many cases, using the
     * {@link #XMPPConnection(String)} constructor is a better approach.<p>
     * <p/>
     * Note that XMPPConnection constructors do not establish a connection to the server
     * and you must call {@link #connect()}.<p>
     * <p/>
     *
     * The CallbackHandler will only be used if the connection requires the client provide
     * an SSL certificate to the server. The CallbackHandler must handle the PasswordCallback
     * to prompt for a password to unlock the keystore containing the SSL certificate.
     *
     * @deprecated call {@link ConnectionConfiguration#setCallbackHandler} and use {@link XMPPConnection#XMPPConnection(ConnectionConfiguration)}.
     * @param config the connection configuration.
     * @param callbackHandler the CallbackHandler used to prompt for the password to the keystore.
     */
    public XMPPConnection(ConnectionConfiguration config, CallbackHandler callbackHandler) {
        this(config, callbackHandler, null);
    }

    /** The primary constructor. */
    private XMPPConnection(ConnectionConfiguration config, CallbackHandler callbackHandler, String serviceName) {
        super(config);
        if(serviceName != null)
            this.config.setServiceName(serviceName);
        if(callbackHandler != null)
            this.config.setCallbackHandler(callbackHandler);

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
    }

    @Override
    public synchronized void login(String username, String password, String resource) throws XMPPException {
        // Do partial version of nameprep on the username.
        username = username.toLowerCase().trim();

        performLogin(username, password, resource);

        // Create the roster if it is not a reconnection or roster already created by getRoster()
        if (this.roster == null) {
            this.roster = new Roster(this);
        }
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

        // Create the roster if it is not a reconnection or roster already created by getRoster()
        if (this.roster == null) {
            this.roster = new Roster(this);
        }
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

        this.setWasAuthenticated(authenticated);
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

        wasAuthenticated = false;
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
     * Registers a packet interceptor with this connection. The interceptor will be
     * invoked every time a packet is about to be sent by this connection. Interceptors
     * may modify the packet to be sent. A packet filter determines which packets
     * will be delivered to the interceptor.
     *
     * @param packetInterceptor the packet interceptor to notify of packets about to be sent.
     * @param packetFilter      the packet filter to use.
     * @deprecated replaced by {@link Connection#addPacketInterceptor(PacketInterceptor, PacketFilter)}.
     */
    public void addPacketWriterInterceptor(PacketInterceptor packetInterceptor,
            PacketFilter packetFilter) {
        addPacketInterceptor(packetInterceptor, packetFilter);
    }

    /**
     * Removes a packet interceptor.
     *
     * @param packetInterceptor the packet interceptor to remove.
     * @deprecated replaced by {@link Connection#removePacketInterceptor(PacketInterceptor)}.
     */
    public void removePacketWriterInterceptor(PacketInterceptor packetInterceptor) {
        removePacketInterceptor(packetInterceptor);
    }

    /**
     * Registers a packet listener with this connection. The listener will be
     * notified of every packet that this connection sends. A packet filter determines
     * which packets will be delivered to the listener. Note that the thread
     * that writes packets will be used to invoke the listeners. Therefore, each
     * packet listener should complete all operations quickly or use a different
     * thread for processing.
     *
     * @param packetListener the packet listener to notify of sent packets.
     * @param packetFilter   the packet filter to use.
     * @deprecated replaced by {@link #addPacketSendingListener(PacketListener, PacketFilter)}.
     */
    public void addPacketWriterListener(PacketListener packetListener, PacketFilter packetFilter) {
        addPacketSendingListener(packetListener, packetFilter);
    }

    /**
     * Removes a packet listener for sending packets from this connection.
     *
     * @param packetListener the packet listener to remove.
     * @deprecated replaced by {@link #removePacketSendingListener(PacketListener)}.
     */
    public void removePacketWriterListener(PacketListener packetListener) {
        removePacketSendingListener(packetListener);
    }

    /** Create a new XMPPStream. */
    private static XMPPStream createDataStream(Class<? extends XMPPStream> transport, ConnectionConfiguration config) {
        // Create an instance of this transport.
        Constructor<? extends XMPPStream> constructor;
        try {
            constructor = transport.getConstructor(ConnectionConfiguration.class);
            return constructor.newInstance(config);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Look up the ConnectionData for the given transport and configuration.
     */
    private static XMPPStream.ConnectData lookupConnectionData(Class<? extends XMPPStream> transport,
            ConnectionConfiguration config) throws XMPPException {
        final XMPPStream lookup_data_stream = createDataStream(transport, config);

        // Schedule a timeout.
        int waitTime = SmackConfiguration.getPacketReplyTimeout();
        // waitTime = 99999999;
        TimeoutThread timeoutThread = new TimeoutThread("Connection timeout thread", waitTime, new Runnable() {
            public void run() { lookup_data_stream.disconnect(); }
        });

        try {
            try {
                return lookup_data_stream.getConnectData();
            } finally {
                timeoutThread.cancel();
            }
        } catch(XMPPException e) {
            if(timeoutThread.executed)
                throw new XMPPException("Connection failed. No response from server.");
            else
                throw e;
        }
    }

    /**
     * Initializes the connection, opening an XMPP stream to the server.
     *
     * @throws XMPPException if establishing a connection to the server fails.
     */
    private void connectUsingConfiguration() throws XMPPException {
        // We may have several candidates to connect to: any number of XMPP
        // hosts via SRV discovery, and any number of BOSH hosts via TXT discovery.
        // Try transports in order of preference.
        Vector<Class<? extends XMPPStream>> transportsToAttempt =
            new Vector<Class<? extends XMPPStream>>();
        transportsToAttempt.add(XMPPStreamBOSH.class);
        transportsToAttempt.add(XMPPStreamTCP.class);

        XMPPException firstFailure = null;
        for(Class<? extends XMPPStream> transport: transportsToAttempt) {
            // Look up the connectData for this transport.  Note that we only log failures
            // here and don't throw.  TCP transport lookup, and lookup for an explicit
            // BOSH URL, will never fail; in the fallback case it'll always give us a
            // default host:5222 lookup.
            XMPPStream.ConnectData connectData;
            try {
                connectData = lookupConnectionData(transport, config);
                if(connectData.connectionAttempts() == 0)
                    continue;
            } catch(XMPPException e) {
                continue;
            }

            // Attempt to connect using this transport.  If the transport discovers more
            // than one server to connect to, try each in order.  Note that timeouts are
            // per-server.
            for(int i = 0; i < connectData.connectionAttempts(); ++i) {
                if(data_stream != null)
                    throw new AssertionError("data_stream should be null");

                data_stream = createDataStream(transport, config);
                try {
                    connectUsingConfigurationAttempt(connectData, i);
                    return;
                } catch(XMPPException e) {
                    // On failure, connectUsingConfigurationAttempt always clears data_stream.
                    if(data_stream != null)
                        throw new AssertionError("connectUsingConfigurationAttempt failed, but left data_stream set");

                    firstFailure = e;
                }
            }
        }

        // We didn't connect.  Report the first failure other than remote_server_not_found
        // as the error.
        throw firstFailure;
    }

    static class TimeoutThread extends Thread {
        long waitTime;
        boolean executed = false;
        Runnable task;
        TimeoutThread(String name, long ms, Runnable task) {
            setName(name);
            waitTime = ms;
            this.task = task;
            start();
        }
        public void run() {
            try {
                Thread.sleep(waitTime);
            } catch(InterruptedException e) {
                return;
            }

            task.run();
            executed = true;
        }

        public void cancel() {
            interrupt();
            ThreadUtil.uninterruptibleJoin(this);
        }
    };

    private void beginConnection(XMPPStream.ConnectData connectData, int attempt) throws XMPPException {
        // Schedule a timeout.
        int waitTime = SmackConfiguration.getPacketReplyTimeout();
        TimeoutThread timeoutThread = new TimeoutThread("Connection timeout thread", waitTime, new Runnable() {
            public void run() { shutdown(); }
        });

        try {
            try {
                data_stream.initializeConnection(connectData, attempt, packetReader.getPacketCallbacks());
            } finally {
                timeoutThread.cancel();
            }
        } catch(XMPPException e) {
            // On timeout, ignore the connection-closed exception and throw a cleaner one.
            if(timeoutThread.executed)
                throw new XMPPException("Connection failed. No response from server.");
            else
                throw e;
        }
    }

    private void connectUsingConfigurationAttempt(XMPPStream.ConnectData connectData, int attempt) throws XMPPException {
        data_stream.setReadWriteEvents(readEvent, writeEvent);

        // Start the packet writer.  This can't fail, and it won't do anything until
        // we receive packets.
        packetWriter.startup();
        packetReader.startup();

        readyForDisconnection = false;

        PacketCollector<ReceivedPacket> coll =
            this.createPacketCollector(new ReceivedPacketFilter("features", "http://etherx.jabber.org/streams"),
                ReceivedPacket.class);

        try {
            // Tell data_stream to initialize the connection.
            beginConnection(connectData, attempt);

            // Connection is successful.
            connected = true;

            // A <features/> packet has been received.  Read it; we'll need it for login.
            initialFeatures = coll.getResult(0);
        }
        catch (XMPPException ex) {
            // An exception occurred in setting up the connection. Make sure we shut down the
            // readers and writers and close the socket.
            shutdown();
            throw ex;        // Everything stopped. Now throw the exception.
        } finally {
            coll.cancel();
        }

        for(Element node: XmlUtil.getChildElements(initialFeatures.getElement())) {
            if(node.getLocalName().equals("register") &&
               node.getNamespaceURI().equals("http://jabber.org/features/iq-register")) {
                getAccountManager().setSupportsAccountCreation(true);
            }
        }

        if (isFirstInitialization) {
            isFirstInitialization = false;

            // Notify listeners that a new connection has been established
            for (ConnectionCreationListener listener: getConnectionCreationListeners()) {
                listener.connectionCreated(XMPPConnection.this);
            }
        }
        else if (!wasAuthenticated) {
            notifyReconnection();
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

    /**
     * Establishes a connection to the XMPP server and performs an automatic login
     * only if the previous connection state was logged (authenticated). It basically
     * creates and maintains a socket connection to the server.<p>
     * <p/>
     * Listeners will be preserved from a previous connection if the reconnection
     * occurs after an abrupt termination.
     *
     * @throws XMPPException if an error occurs while trying to establish the connection.
     *      Two possible errors can occur which will be wrapped by an XMPPException --
     *      UnknownHostException (XMPP error code 504), and IOException (XMPP error code
     *      502). The error codes and wrapped exceptions can be used to present more
     *      appropiate error messages to end-users.
     */
    public void connect() throws XMPPException {
        // If we're already connected, or if we've disconnected but havn't yet cleaned
        // up, shut down.
        shutdown();

        // Establishes the connection, readers and writers
        connectUsingConfiguration();
        // Automatically makes the login if the user was previouslly connected successfully
        // to the server and the connection was terminated abruptly
        if (connected && wasAuthenticated) {
            // Make the login
            try {
                if (isAnonymous()) {
                    // Make the anonymous login
                    loginAnonymously();
                }
                else {
                    login(config.getUsername(), config.getPassword(),
                            config.getResource());
                }
                notifyReconnection();
            }
            catch (XMPPException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Sets whether the connection has already logged in the server.
     *
     * @param wasAuthenticated true if the connection has already been authenticated.
     */
    private void setWasAuthenticated(boolean wasAuthenticated) {
        if (!this.wasAuthenticated) {
            this.wasAuthenticated = wasAuthenticated;
        }
    }

    /** Write a list of packets to the stream.  Used by PacketWriter. */
    protected void writePacket(Collection<Packet> packets) throws XMPPException {
        StringBuffer data = new StringBuffer();
        for(Packet packet: packets)
            data.append(packet.toXML());

        data_stream.writePacket(data.toString());
    }

    /**
     * Sends a notification indicating that the connection was reconnected successfully.
     */
    protected void notifyReconnection() {
        // Notify connection listeners of the reconnection.
        for (ConnectionListener listener: getConnectionListeners()) {
            try {
                listener.reconnectionSuccessful();
            }
            catch (Exception e) {
                // Catch and print any exception so we can recover
                // from a faulty listener
                e.printStackTrace();
            }
        }
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
