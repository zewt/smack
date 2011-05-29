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

import org.jivesoftware.smack.Connection.ListenerWrapper;
import org.jivesoftware.smack.XMPPStream.PacketCallback;
import org.jivesoftware.smack.SynchronousPacketListener;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smack.util.ThreadUtil;
import org.jivesoftware.smack.util.XmlPullParserDom;
import org.jivesoftware.smack.util.XmlUtil;
import org.w3c.dom.Element;
import org.xmlpull.v1.XmlPullParser;

import java.util.concurrent.*;

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
    }

    class ReaderPacketCallbacks extends XMPPStream.PacketCallback {
        public void onPacket(Element packet) {
            parsePacket(packet);
        }
        public void onError(XMPPException error) {
            handleError(error);
        }
    };

    /**
     * Start the reader thread, blocking until the transport is established.  If
     * an exception is thrown, the caller must shut down the data stream to ensure
     * the reader thread exits, and call our shutdown() method.
     *
     * @throws XMPPException if the connection could not be established
     */
    public void startup() throws XMPPException {
        if(listenerExecutor != null)
            throw new RuntimeException("ReaderThread.startup called while already connected");

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

        class TimeoutThread extends Thread {
            long waitTime;
            boolean timedOut = false;
            TimeoutThread(long ms) {
                waitTime = ms;
            }
            public void run() {
                try {
                    Thread.sleep(waitTime);
                } catch(InterruptedException e) {
                    return;
                }

                timedOut = true;
                connection.shutdown();
            }

            public void cancel() {
                interrupt();
                ThreadUtil.uninterruptibleJoin(this);
            }
        };

        // Schedule a timeout.
        int waitTime = SmackConfiguration.getPacketReplyTimeout();
        TimeoutThread timeoutThread = new TimeoutThread(waitTime);
        timeoutThread.setName("Connection timeout thread");
        timeoutThread.start();

        boolean waitingForEstablishedConnection = true;
        try {
            try {
                connection.initializeConnection(new ReaderPacketCallbacks());
            } finally {
                timeoutThread.cancel();
            }
        } catch(XMPPException e) {
            // On timeout, ignore the connection-closed exception and throw a cleaner one.
            if(timeoutThread.timedOut)
                throw new XMPPException("Connection failed. No response from server.");
            throw e;
        }
    }

    /**
     * Shuts the packet reader down.
     *
     * The caller must first shut down the data stream to ensure the thread will exit.
     */
    public void shutdown() {
        // Shut down the listener executor.
        if(listenerExecutor != null) {
            listenerExecutor.shutdown();
            listenerExecutor = null;
        }
    }

    /**
     * Parse top-level packets in order to process them further.
     *
     * @param thread the thread that is being used by the reader to parse incoming packets.
     */
    private void parsePacket(Element packet) {
        try {
            /* Convert the stanza to an XmlPullParser. */
            XmlPullParser parser = new XmlPullParserDom(packet, true);

            for ( ; parser.getEventType() != XmlPullParser.END_DOCUMENT; parser.next() ) {
                if(parser.getEventType() != XmlPullParser.START_TAG)
                    continue;

                Packet receivedPacket;
                if (parser.getName().equals("message")) {
                    receivedPacket = PacketParserUtils.parseMessage(parser);
                }
                else if (parser.getName().equals("iq")) {
                    receivedPacket = PacketParserUtils.parseIQ(parser, connection);
                }
                else if (parser.getName().equals("presence")) {
                    receivedPacket = PacketParserUtils.parsePresence(parser);
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
            }
        } catch (XMPPException e) {
            handleError(e);
        } catch (Exception e) {
            e.printStackTrace();
            handleError(new XMPPException(e));
        }
    }

    private void handleError(XMPPException e) {
        connection.readerThreadException(e);

        // Wake up any thread waiting for a packet collector, so they notice
        // that we're disconnected.  This must be done after notifying connection,
        // so connection.isConnected returns false.
        if(connection.isConnected())
            throw new AssertionError("Should be disconnected");

        for (PacketCollector collector: connection.getPacketCollectors()) {
            collector.connectionLost();
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