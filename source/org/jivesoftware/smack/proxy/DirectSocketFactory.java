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
import java.net.InetSocketAddress;
import java.net.Socket;

import org.jivesoftware.smack.XMPPException;

class DirectSocketFactory extends SocketConnectorFactory
{
    public SocketConnector createConnector(Socket socket) {
        return new DirectSocketConnector(socket);
    }
}

class DirectSocketConnector extends CancellableSocketConnector
{
    public DirectSocketConnector(Socket socket) { super(socket); }
    
    protected void connectSocketInternal(String host, int port) throws XMPPException, IOException {
        InetAddress ip = lookupHostIP(host);
        
        // Don't pass the InetAddress directly to InetSocketAddress; it'll do a reverse IP
        // lookup, which we don't want.
        String ipString = ip.getHostAddress();
        socket.connect(new InetSocketAddress(ipString, port));
    }
}
