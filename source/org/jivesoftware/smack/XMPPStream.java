package org.jivesoftware.smack;

import java.io.IOException;

import org.jivesoftware.smack.util.ObservableReader;
import org.jivesoftware.smack.util.ObservableWriter;
import org.w3c.dom.Element;

public abstract class XMPPStream
{
    /**
     * Begin establishing the connection.  Returns after the connection has been
     * established, or throws XMPPException.
     * 
     * @throws XMPPException if an error occurs during connection
     */
    public abstract void initializeConnection() throws XMPPException;
    
    /**
     * Send the given packets to the server asynchronously.  This function will not
     * block.  If the connection has already been closed, throws IOException. 
     */
    public abstract void writePacket(String packet) throws IOException;

    /**
     * Permanently close the connection, flushing any pending messages and cleanly
     * disconnecting the session.  If non-null and the connection is not already
     * closed, the given packets will be sent in the disconnection message.  This
     * function may block.
     */
    public abstract void close(String packet);

    /**
     * Forcibly disconnect the connection.  Future calls to readPacket will return
     * null.  If another thread is currently blocking in readPacket, it will return
     * null immediately. 
     */
    public abstract void disconnect();
    
    /**
     * Indicate to the stream that a stream reset has occurred.
     * @throws IOException
     */
    public abstract void streamReset() throws XMPPException;
    
    /**
     * Returns a single parsed XML stanza, blocking if necessary.  If the stream is
     * closed cleanly by either side, return null.
     * 
     * @return a parsed XMPP stanza.
     * @throws XMPPException if an error occurs while reading or parsing the response.
     */
    public abstract Element readPacket() throws InterruptedException, XMPPException;
    
    /**
     * Returns the current connection ID, or null if the connection hasn't
     * established an ID yet.
     * 
     * @return the connection ID or null.
     */
    public abstract String getConnectionID();

    /**
     * Set the read and write events for this connection, which may be observed to monitor
     * incoming and outgoing data.  This must be called before {@link #initializeConnection()}.
     */
    public abstract void setReadWriteEvents(ObservableReader.ReadEvent readEvent, ObservableWriter.WriteEvent writeEvent);

    /**
     * If service discovery is in use, set the index of the discovered resource to connect
     * to.  For example, when discovering XMPP servers via SRV, setDiscoveryIndex(5) indicates
     * that the 6th SRV entry by priority order will be attempted.
     * <p>
     * If index is greater than the highest discovered resource, or if this service does not
     * support discovery and index is greater than 0, initializeConnection will raise an
     * exception with a condition of remote_server_not_found.
     * <p>
     * This must be called before {@link #initializeConnection()}.
     */
    public abstract void setDiscoveryIndex(int index);

    /**
     * Returns true if the connection to the server is secure.
     *
     * @return true if the connection to the server has successfully negotiated TLS.
     */
    public abstract boolean isSecureConnection();

    /**
     * @return true if the connection to the server is compressed.
     */
    public abstract boolean isUsingCompression();
};
