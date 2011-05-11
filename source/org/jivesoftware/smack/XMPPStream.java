package org.jivesoftware.smack;

import java.io.IOException;
import java.io.Writer;
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
     * Retrieve the writer for sending packets.
     * @return Writer
     */
    public abstract Writer getWriter();

    /**
     * Permanently close the connection, flushing any pending messages and cleanly
     * disconnecting the session.  This function may block.
     */
    public abstract void close();

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
     * Return the ObservableReader for this connection; users may attach observers to
     * it to monitor incoming data.
     * 
     * @return ObservableReader
     */
    public abstract ObservableReader getObservableReader();

    /**
     * Return the ObservableWriter for this connection; users may attach observers to
     * it to monitor outgoing data.
     * 
     * @return ObservableWriter
     */
    public abstract ObservableWriter getObservableWriter();
    
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
