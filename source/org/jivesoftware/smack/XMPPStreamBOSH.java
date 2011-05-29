package org.jivesoftware.smack;

import java.io.IOException;
import java.io.StringReader;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.Vector;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLSocket;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.XMPPStream.ConnectData;
import org.jivesoftware.smack.XMPPStream.PacketCallback;
import org.jivesoftware.smack.XMPPStreamTCP.ConnectDataTCP;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.util.DNSUtil;
import org.jivesoftware.smack.util.ObservableReader;
import org.jivesoftware.smack.util.ObservableWriter;
import org.jivesoftware.smack.util.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.kenai.jbosh.AbstractBody;
import com.kenai.jbosh.BOSHClient;
import com.kenai.jbosh.BOSHClientConfig;
import com.kenai.jbosh.BOSHClientConnEvent;
import com.kenai.jbosh.BOSHClientConnListener;
import com.kenai.jbosh.BOSHClientRequestListener;
import com.kenai.jbosh.BOSHClientResponseListener;
import com.kenai.jbosh.BOSHException;
import com.kenai.jbosh.BOSHMessageEvent;
import com.kenai.jbosh.BodyQName;
import com.kenai.jbosh.ComposableBody;

public class XMPPStreamBOSH extends XMPPStream
{
    private URI uri = null;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition cond = lock.newCondition();
    
    // bosh_client must only be accessed while locked, and only when connectionClosed is false.
    private BOSHClient bosh_client;
    private boolean connectionClosed = false;

    /** Return true if the connection is secure (encrypted with a verified certificate). */
    public boolean isSecureConnection() { return usingSecureConnection; }
    private boolean usingSecureConnection = false;

    public void writePacket(String packet) throws XMPPException {
        if(connectionClosed)
            throw new XMPPException("Wrote a packet while the connection was closed");

        try {
            // Note that this will block if the packet can't be sent immediately.
            bosh_client.send(createBoshPacket(packet).build());
        } catch(BOSHException e) {
            throw new XMPPException("Error writing BOSH packet", e);
        }
    }

    // Although compression may or may not be in use by the HTTP stream, that can
    // vary from connection to connection, and we won't have any meaningful response
    // if the connection is inactive.  Just return false.
    public boolean isUsingCompression() { return false; }

    private ObservableReader.ReadEvent readEvent;
    private ObservableWriter.WriteEvent writeEvent;

    String authID;
    public String getConnectionID() { return authID; }

    public void setReadWriteEvents(ObservableReader.ReadEvent readEvent, ObservableWriter.WriteEvent writeEvent) {
        this.writeEvent = writeEvent;
        this.readEvent = readEvent;
    }

    ConnectionConfiguration config;

    public XMPPStreamBOSH(ConnectionConfiguration config)
    {
        this.uri = config.getBoshURI();
        this.config = config;
        connectionClosed = true;
    }

    private PacketCallback callback;

    class ConnectDataBOSH extends ConnectData {
        Vector<URI> addresses = new Vector<URI>();

        int connectionAttempts() {
            return addresses.size();
        }
    };

    public ConnectData getConnectData() throws XMPPException {
        assertNotLocked();

        if(bosh_client != null)
            throw new RuntimeException("The connection has already been initialized");
        if(this.uri == null)
            throw new XMPPException("BOSH is disabled", XMPPError.Condition.remote_server_not_found);

        ConnectDataBOSH data = new ConnectDataBOSH();

        if(this.uri == null)
            return data;

        if(!this.uri.equals(ConnectionConfiguration.AUTO_DETECT_BOSH)) {
            data.addresses.add(this.uri);
            return data;
        }

        if(this.uri == ConnectionConfiguration.AUTO_DETECT_BOSH) {
            // This will return the same results each time, because the weight
            // shuffling is cached.
            // XXX: Figure out how BOSH discovery is supposed to be secured. 
            DNSUtil.XMPPConnectLookup lookup = new DNSUtil.XMPPConnectLookup(config.getServiceName(), "_xmpp-client-xbosh");
            Vector<String> urls = lookup.run();
            // XXX might be null
            if(urls.isEmpty())
                throw new XMPPException("No BOSH servers discovered", XMPPError.Condition.remote_server_not_found);

            for(String url: urls) {
                try {
                    URI uri = new URI(url);

                    // Only allow HTTP and HTTPS.
                    if(uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https"))
                        data.addresses.add(uri);
                } catch (URISyntaxException e) {
                    // throw new XMPPException("Discovered BOSH server has bad URL: " + url);
                }
            }
        }

        return data;
    }

    public void initializeConnection(ConnectData data, int attempt, final PacketCallback userCallback) throws XMPPException
    {
        assertNotLocked();

        if(bosh_client != null)
            throw new RuntimeException("The connection has already been initialized");

        // If BOSH is disabled, then stop attempting this transport.
        if(this.uri == null)
            throw new XMPPException("BOSH is disabled", XMPPError.Condition.remote_server_not_found);

        if(!(data instanceof ConnectDataBOSH))
            throw new IllegalArgumentException("data argument was not created with XMPPStreamBOSH.getConnectData");
        ConnectDataBOSH dataBOSH = (ConnectDataBOSH) data;

        if(attempt >= dataBOSH.addresses.size())
            throw new IllegalArgumentException();

        uri = dataBOSH.addresses.get(attempt);

        // We'll catch this down below, but we throw a different message here.
        if(config.getSecurityMode() == SecurityMode.required && !uri.getScheme().equalsIgnoreCase("https"))
            throw new XMPPException("Discovered BOSH server is not HTTPS, but security required by connection configuration.",
                    XMPPError.Condition.forbidden);

        BOSHClientConfig.Builder cfgBuilder = BOSHClientConfig.Builder.create(uri, config.getServiceName());
        cfgBuilder.setSocketFactory(config.getProxyInfo().getSocketFactory());

        final XMPPSSLSocketFactory xmppSocketFactory = new XMPPSSLSocketFactory(config, config.getServiceName());
        cfgBuilder.setSSLConnector(new com.kenai.jbosh.SSLConnector() {
            public SSLSocket attachSSLConnection(Socket socket, String host, int port) throws IOException {
                return xmppSocketFactory.attachSSLConnection(socket, host, port);
            }
        });

        if(uri.getScheme().equals("http")) {
            if(config.getSecurityMode() == SecurityMode.required)
                throw new XMPPException("BOSH server is not HTTPS, but security required by connection configuration.",
                        XMPPError.Condition.forbidden);
            usingSecureConnection = false;
        }

        bosh_client = BOSHClient.create(cfgBuilder.build());
        bosh_client.addBOSHClientResponseListener(new ResponseListener());
        bosh_client.addBOSHClientConnListener(new ConnectionListener());

        // Pass on requests and responses to observers.
        bosh_client.addBOSHClientResponseListener(new BOSHClientResponseListener() {
            public void responseReceived(BOSHMessageEvent event) {
                if (event.getBody() == null)
                    return;
                readEvent.notifyListeners(event.getBody().toXML());
            }
        });

        bosh_client.addBOSHClientRequestListener(new BOSHClientRequestListener() {
            public void requestSent(BOSHMessageEvent event) {
                if (event.getBody() == null)
                    return;
                writeEvent.notifyListeners(event.getBody().toXML());
            }
        });

        SetupPacketCallback setupCallback = new SetupPacketCallback(userCallback);
        callback = setupCallback;

        try {
            // Send the session creation request and receive the response.
            try {
                bosh_client.send(ComposableBody.builder()
                            .setNamespaceDefinition("xmpp", "urn:xmpp:xbosh")
                            .setAttribute(BodyQName.createWithPrefix("urn:xmpp:xbosh", "version", "xmpp"), "1.0")
                            .build());
            }
            catch(BOSHException e)
            {
                throw new XMPPException("Error connecting to BOSH server", e);
            }

            setupCallback.waitForCompletion();
        } catch(XMPPException e) {
            /* If an exception occurs while we're starting the connection, close it.
             * The connection should only be running on a successful return. */
            // android.util.Log.w("SMACK", "XMPPStreamBOSH: initializeConnection: shutting down client due to error");
            disconnect();
            throw e;
        }

        // We've received the first response, so the first connection has been established.
        // We can now tell if the connection was made insecurely.  We don't need to check
        // SecurityMode here: if it's set to required, an exception was thrown when we first
        // connected the socket.  Note that usingSecureConnection may already be false for
        // other reasons.
        if(xmppSocketFactory != null) {
            CertificateException detail = xmppSocketFactory.getSeenInsecureConnection();
            if(detail != null)
                usingSecureConnection = false;
        }

        connectionClosed = false;
    }

    class SetupPacketCallback extends PacketCallback {
        boolean complete = false;
        XMPPException error = null;

        /* After completing transport setup, the packet callbacks will be changed from this
         * object to the user's callbacks. */
        PacketCallback userCallbacks;

        SetupPacketCallback(PacketCallback userCallbacks) {
            this.userCallbacks = userCallbacks;
        }

        public void onBody(AbstractBody body) {
            assertNotLocked();

            try {
                handleFirstResponse(body);
            } catch(XMPPException e) {
                onError(e);
                return;
            }

            // Switch callbacks to the user's, so ResponseListener sends onPacket
            // calls to it.
            callback = userCallbacks;

            // Wake up waitForCompletion.
            lock.lock();
            try {
                complete = true;
                cond.signalAll();
            } finally {
                lock.unlock();
            }
        }

        // This is never called, since we change to userCallbacks first.
        public void onPacket(Element packet) { }

        public void onError(XMPPException error) {
            assertNotLocked();
            lock.lock();
            try {
                this.error = error;
                cond.signalAll();
            } finally {
                lock.unlock();
            }
        }

        /** Wait until stream negotiation is complete. */
        public void waitForCompletion() throws XMPPException {
            assertNotLocked();
            lock.lock();
            try {
                while(!complete && error == null) {
                    try {
                        cond.await();
                    } catch(InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } finally {
                lock.unlock();
            }

            if(error != null)
                throw new XMPPException(error);
        }
    };

    private void handleFirstResponse(AbstractBody packet) throws XMPPException {
        // Check that secure='1' was sent in the response, indicating that the BOSH->XMPP connection
        // is also secure.
        String secure = packet.getAttribute(BodyQName.create("http://jabber.org/protocol/httpbind", "secure"));
        if(secure == null || (!secure.equalsIgnoreCase("true") && !secure.equals("1"))) {
            usingSecureConnection = false;

            if(config.getSecurityMode() == ConnectionConfiguration.SecurityMode.required) {
                throw new XMPPException("The BOSH->XMPP session is not secure, " +
                        "but the configuration requires a secure connection.",
                        XMPPError.Condition.forbidden);
            }
        }

        // Over BOSH, XMPP's <body id> is transmitted as authid.
        authID = packet.getAttribute(BodyQName.create("http://jabber.org/protocol/httpbind", "authid"));

        // Update the service name from <body from>, if provided.
        String from = packet.getAttribute(BodyQName.create("http://jabber.org/protocol/httpbind", "from"));
        if(from != null)
            config.setServiceName(from);
    }

    public void gracefulDisconnect(String packet)
    {
        assertNotLocked();
        // android.util.Log.w("SMACK", "XMPPStreamBOSH: close()");

        try {
            // If any stanzas are waiting to be sent, send them in the disconnect message.
            bosh_client.disconnect(createBoshPacket(packet).build());
        }
        catch(BOSHException e)
        {
            // If the disconnect() fails for some reason, forcibly close the connection.
            // android.util.Log.w("SMACK", "XMPPStreamBOSH: sending disconnect(): error");
            e.printStackTrace();
            disconnect();
            return;
        }

        // We've sent the terminate packet.  Wait for the stream to close; we'll
        // receive a connectionEvent, which will call disconnect() and set connectionClosed.
        // android.util.Log.w("SMACK", "XMPPStreamBOSH: waiting for disconnect");
        long waitUntil = System.currentTimeMillis() + SmackConfiguration.getPacketReplyTimeout();
        lock.lock();
        try {
            while(!connectionClosed) {
                long ms = waitUntil - System.currentTimeMillis();
                if(ms <= 0)
                    break;
                try {
                    cond.await(ms, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } finally {
            lock.unlock();
        }

        // android.util.Log.w("SMACK", "XMPPStreamBOSH: done waiting, " + (connectionClosed? "connection is closed":"connection is not closed"));

        // In case we timed out above and the stream isn't closed yet, forcibly close it.
        disconnect();
    }

    public void disconnect() {
        assertNotLocked();

        lock.lock();
        try {
            if(connectionClosed)
                return;

            bosh_client.close();

            connectionClosed = true;
            cond.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /**
     * A stream reset is required, usually due to SASL authentication completing.
     * Instruct the BOSH server to perform the restart.
     */
    public void streamReset() throws XMPPException {
        // We're supposed to check for <body restartlogic='true'>, which tells us that the server supports
        // stream restarts.  If it's not present, we can't restart the stream, which means we can't
        // authenticate via SASL.  However, the spec also notes correctly that older BOSH implementations
        // don't advertise restartlogic (despite supporting it).  If we refuse to authenticate
        // when restartlogic isn't present, then we'll break logins on older servers.  This really
        // isn't very useful: a BOSH server that we effectively can't authenticate through is useless,
        // so for now just pretend they all support stream restarts.
        assertNotLocked();

        try {
            /* Make sure any written data is flushed and sent to the server.  According
             * to XEP-0206, any stanzas we put in a <body restart='true'> packet will be
             * ignored. */
            if(connectionClosed)
                throw new XMPPException("Connection has closed");

            bosh_client.send(ComposableBody.builder()
                    .setNamespaceDefinition("xmpp", "urn:xmpp:xbosh")
                    .setAttribute(BodyQName.createWithPrefix("urn:xmpp:xbosh", "version", "xmpp"), "1.0")
                    .setAttribute(BodyQName.createWithPrefix("urn:xmpp:xbosh", "restart", "xmpp"), "true")
                    .build());
        }
        catch(BOSHException e) {
            throw new XMPPException("BOSH error while sending xmpp:restart", e);
        }
    }

    private static ComposableBody.Builder createBoshPacket(String packet) {
        ComposableBody.Builder builder = ComposableBody.builder()
            .setNamespaceDefinition("xmpp", "urn:xmpp:xbosh")
            .setAttribute(BodyQName.createWithPrefix("urn:xmpp:xbosh", "version", "xmpp"), "1.0");

        if(packet != null) {
            builder.setPayloadXML(packet);
        }

        return builder;
    }

    private class ResponseListener implements BOSHClientResponseListener
    {
        public void responseReceived(BOSHMessageEvent event)
        {
            assertNotLocked();

            AbstractBody body = event.getBody();

            String xml = body.toXML();
            Element bodyNode;

            try {
                DocumentBuilder docBuilder = XmlUtil.getDocumentBuilder();
                Document doc = docBuilder.parse(new InputSource(new StringReader(xml)));

                // Retrieve <body>.
                bodyNode = (Element) doc.getFirstChild();
            }
            catch(IOException e) {
                callback.onError(new XMPPException("Error reading packet", e));
                return;
            }
            catch(SAXException e) {
                callback.onError(new XMPPException("Error reading packet", e));
                return;
            }

            if(callback instanceof SetupPacketCallback) {
                SetupPacketCallback setupCallbacks = (SetupPacketCallback) callback;
                setupCallbacks.onBody(body);
            }

            // The children of <body> are the XMPP payloads.
            NodeList nodes = bodyNode.getChildNodes();
            for(int i = 0; i < nodes.getLength(); ++i) {
                Node node = nodes.item(i);
                if(!(node instanceof Element))
                    continue;
                callback.onPacket((Element) node);
            }
        }
    }

    private class ConnectionListener implements BOSHClientConnListener
    {
        public void connectionEvent(BOSHClientConnEvent connEvent)
        {
            assertNotLocked();

            Throwable be = connEvent.getCause();

            // This is a hack: when the session is forcibly closed by calling
            // bosh_client.close(), jbosh triggers an error, but that shouldn't
            // actually be treated as one.  jbosh should use a separate exception
            // class for this, so we can distinguish this case sanely, or just
            // send this case as a disconnection instead of disconnection error.
            boolean ignoredError = be != null && be.getMessage().equals("Session explicitly closed by caller");

            if(connEvent.isError() && !ignoredError) {
                callback.onError(new XMPPException(be));
            }

            if(!connEvent.isConnected() && !connectionClosed) {
                disconnect();
            }
        }
    }

    private void assertNotLocked() {
        if(lock.isHeldByCurrentThread())
            throw new RuntimeException("Lock should not be held");
    }
};
