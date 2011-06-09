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

package org.jivesoftware.smack.proxy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Vector;

import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.proxy.SocketConnectorFactory.SocketConnector;
import org.jivesoftware.smack.util.DNSUtil.AddressLookup;

/**
 * A common base class for cancellable SocketConnectors.  All high-level SocketConnectors
 * should use this.
 * <p>
 * When a SocketConnector is cancelled, its socket will be closed, causing operations on
 * it to throw.  This also implements cancellable DNS lookups.
 */
abstract class CancellableSocketConnector extends SocketConnector
{
    protected final Socket socket;
    protected AddressLookup dnsLookup;
    private boolean cancelled = false;

    CancellableSocketConnector(Socket socket) { this.socket = socket; }

    /**
     * Look up the specified host, returning an {@link InetAddress}.  If the operation
     * is cancelled, an XMPPException will be thrown. 
     */
    protected InetAddress lookupHostIP(String host) throws XMPPException {
        AddressLookup lookup;
        synchronized(this) {
            if(cancelled)
                throw new XMPPException("Connection cancelled");

            lookup = new AddressLookup(host);
            dnsLookup = lookup;
        }

        // Look up the host.
        Vector<InetAddress> ips = lookup.run();

        synchronized(this) {
            dnsLookup = null;

            if(ips == null)
                throw new XMPPException("Connection cancelled");

            if(ips.size() == 0)
                throw new XMPPException("Couldn't resolve host: " + host);

            // Although the address might have multiple A records, we only try the first.  DNS-
            // based load balancing for XMPP should be done using SRV records, not A records.
            return ips.get(0);
        }
    }

    public void cancel() {
        synchronized(this) {
            cancelled = true;

            if(dnsLookup != null)
                dnsLookup.cancel();
        }

        try {
            socket.close();
        } catch(IOException e) {
            throw new RuntimeException(e);
        }
    }    

    public void connectSocket(String host, int port) throws XMPPException, IOException {
        // As a shortcut for implementations, ensure that the socket is always closed on exception.
        // Derived classes should implement connectSocketInternal.
        boolean success = false;
        try {
            connectSocketInternal(host, port);
            success = true;
        } finally {
            if(!success) {
                try {
                    socket.close();
                } catch(IOException e) {
                    // Closing the socket should never actually fail.
                    throw new RuntimeException(e);
                }
            }
        }
    }
    
    abstract protected void connectSocketInternal(String host, int port) throws XMPPException, IOException;
};
