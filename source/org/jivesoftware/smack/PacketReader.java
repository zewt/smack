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

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import org.jivesoftware.smack.Connection.ListenerWrapper;
import org.jivesoftware.smack.XMPPStream.PacketCallback;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.ReceivedPacket;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smack.util.XmlPullParserDom;
import org.w3c.dom.Element;
import org.xmlpull.v1.XmlPullParser;

/**
 * Listens for XML traffic from the XMPP server and parses it into packet objects.
 * The packet reader also invokes all packet listeners and collectors.<p>
 *
 * @see Connection#createPacketCollector
 * @see Connection#addPacketListener
 * @author Matt Tucker
 */
class PacketReader {
    private ExecutorService listenerExecutor;

    private XMPPConnection connection;

    protected PacketReader(final XMPPConnection connection) {
        this.connection = connection;

        // Create an executor to deliver incoming packets to listeners. We'll use a single
        // thread with an unbounded queue.
        listenerExecutor = Executors.newSingleThreadExecutor(new ThreadFactory() {
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable,
                        "Smack Listener Processor (" + connection.connectionCounterValue + ")");
                thread.setDaemon(true);
                return thread;
            }
        });
    }
    
    /**
     * Shuts the packet reader down.
     */
    public void shutdown() {
        // Shut down the listener executor.
        ExecutorService executorRef;
        synchronized(this) {
            executorRef = listenerExecutor;
            listenerExecutor = null;
        }

        if(executorRef != null) {
            executorRef.shutdown();
            try {
                // There's no non-timeout awaitTermination method, but we want to wait
                // indefinitely.
                executorRef.awaitTermination(99999999, TimeUnit.SECONDS);
            } catch(InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Parse top-level packets in order to process them further.
     *
     * @param thread the thread that is being used by the reader to parse incoming packets.
     */
    void parsePacket(Element packet) {
        try {
            /* Convert the stanza to an XmlPullParser. */
            XmlPullParser parser = new XmlPullParserDom(packet, true);

            if(parser.getEventType() == XmlPullParser.START_DOCUMENT)
                parser.next();
            
            if(parser.getEventType() != XmlPullParser.START_TAG)
                return;

            Packet receivedPacket;
            if (parser.getName().equals("message")) {
                receivedPacket = PacketParserUtils.parseMessage(packet);
            }
            else if (parser.getName().equals("iq")) {
                receivedPacket = PacketParserUtils.parseIQ(parser, connection);
            }
            else if (parser.getName().equals("presence")) {
                receivedPacket = PacketParserUtils.parsePresence(packet);
            }
            else if (parser.getName().equals("error")) {
                throw new XMPPException(PacketParserUtils.parseStreamError(parser));
            } else {
                // Treat any unknown packet types generically.
                receivedPacket = new ReceivedPacket(packet);
            }

            for (ListenerWrapper listenerWrapper : connection.recvListeners.values()) {
                if(listenerWrapper.isSynchronous())
                    listenerWrapper.notifyListener(receivedPacket);
            }

            // Loop through all collectors and notify the appropriate ones.
            for (PacketCollector collector: connection.getPacketCollectors())
                collector.processPacket(receivedPacket);

            // Deliver the received packet to listeners.
            listenerExecutor.submit(new ListenerNotification(receivedPacket));
        } catch (RuntimeException e) {
            throw e;
        } catch (XMPPException e) {
            connection.handleError(e);
        } catch (Exception e) {
            e.printStackTrace();
            connection.handleError(new XMPPException(e));
        }
    }

    /**
     * A runnable to notify all listeners of a packet.
     */
    private class ListenerNotification implements Runnable {

        private Packet packet;

        public ListenerNotification(Packet packet) {
            this.packet = packet;
        }

        public void run() {
            // Listeners are run synchronously to this thread.  Run them before
            // collectors, so a collector can be used to wait until all listeners
            // on a packet have been run.
            for (ListenerWrapper listenerWrapper : connection.recvListeners.values()) {
                if(!listenerWrapper.isSynchronous())
                    listenerWrapper.notifyListener(packet);
            }
        }
    }
}