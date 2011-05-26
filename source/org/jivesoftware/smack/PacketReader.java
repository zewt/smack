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

    private Thread readerThread;
    private ExecutorService listenerExecutor;

    private XMPPConnection connection;
    private boolean done;

    protected PacketReader(final XMPPConnection connection) {
        this.connection = connection;
        done = false;
    }

    /**
     * Starts the packet reader thread and returns once a connection to the server
     * has been established. A connection will be attempted for a maximum of five
     * seconds. An XMPPException will be thrown if the connection fails.
     *
     * @throws XMPPException if the server fails to send an opening stream back
     *      for more than five seconds.
     */
    private Semaphore connectionSemaphore;
    private XMPPException connectionException;
    private void connectionEstablished() {
        connectionSemaphore.release();
    }
    private void connectionEstablishError(XMPPException e) {
        connectionException = e;
        connectionSemaphore.release();
    }

    /**
     * Start the reader thread, blocking until the transport is established.  If
     * an exception is thrown, the caller must shut down the data stream to ensure
     * the reader thread exits, and call our shutdown() method.
     *
     * @throws XMPPException if the connection could not be established
     */
    public void startup() throws XMPPException {
        if(readerThread != null)
            throw new RuntimeException("ReaderThread.startup called while already running");

        done = false;
        connectionException = null;
        connectionSemaphore = new Semaphore(0);

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

        // Begin connecting.
        readerThread = new Thread() {
            public void run() {
                parsePackets(this);
            }
        };
        readerThread.setName("Smack Packet Reader (" + connection.connectionCounterValue + ")");
        readerThread.setDaemon(true);
        readerThread.start();

        // Wait until the connection is established before returning.
        int waitTime = SmackConfiguration.getPacketReplyTimeout();

        try {
            if(!connectionSemaphore.tryAcquire(3 * waitTime, TimeUnit.MILLISECONDS)) {
                /* The connection timed out. */
                throw new XMPPException("Connection failed. No response from server.");
            }
        }
        catch (InterruptedException ie) {
            throw new XMPPException("Connection interrupted", ie);
        }

        // If an exception occurred during connection, re-throw it.
        if (connectionException != null)
            throw connectionException;
    }

    /**
     * Shuts the packet reader down.
     *
     * The caller must first shut down the data stream to ensure the thread will exit.
     */
    public void shutdown() {
        if(readerThread == Thread.currentThread())
            throw new AssertionError("shutdown() can't be called from the packet reader thread");

        // The actual shutdown happens due to the caller closing the data stream.
        done = true;

        // Do nothing if we're already shut down.
        if(readerThread == null)
            return;

        // Wait for the reader thread to exit.  It's the caller's responsibility to ensure
        // that the underlying reader returns an EOF before calling this function.
        ThreadUtil.uninterruptibleJoin(readerThread);
        readerThread = null;

        // Shut down the listener executor.
        listenerExecutor.shutdown();
    }

    /** Assert that the current thread is not the reader thread. */
    public void assertNotInThread() {
        if(Thread.currentThread() == readerThread)
            throw new RuntimeException("Call from within reader thread prohibited");
    }

    /**
     * Parse top-level packets in order to process them further.
     *
     * @param thread the thread that is being used by the reader to parse incoming packets.
     */
    private void parsePackets(Thread thread) {
        boolean waitingForEstablishedConnection = true;
        try {
            try {
                connection.initializeConnection();
            } catch(XMPPException e) {
                /* Before connection, users can't yet attach error listeners.  Errors before
                 * connection are thrown from startup(). */
                connectionEstablishError(e);
                return;
            }

            while(!done) {
                // Read the next packet.
                Element packet = this.connection.readPacket();

                if(packet == null) {
                    // The session has terminated.
                    throw new XMPPException("Connection closed");
                }

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
                    }
                    else if (parser.getName().equals("features")) {
                        if(waitingForEstablishedConnection) {
                            /* When initializeConnection returns, the connection is established and ready to use.
                             * However, don't signal to continue until we receive the first packet, which will
                             * be <features/>.  Otherwise, we're not ready for login() to be called. */
                            connectionEstablished();
                            waitingForEstablishedConnection = false;
                        }

                        receivedPacket = parseFeatures(packet);
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
            }
        }
        catch (RuntimeException e) {
            throw e; // don't handle unchecked exceptions below
        } catch (Exception e) {
            if(!(e instanceof XMPPException))
                e.printStackTrace();
            if(waitingForEstablishedConnection) {
                waitingForEstablishedConnection = false;
                // If waitingForEstablishedConnection is true, startup() is still waiting for
                // us, so deliver the exception there instead.
                if(e instanceof XMPPException)
                    connectionEstablishError((XMPPException) e);
                else
                    connectionEstablishError(new XMPPException(e));
            }
            else if (!done) {
                // Close the connection and notify connection listeners of the
                // error.
                done = true;
                connection.readerThreadException(e);
            }

            // Wake up any thread waiting for a packet collector, so they notice
            // that we're disconnected.  This must be done after notifying connection,
            // so connection.isConnected returns false.
            if(connection.isConnected())
                throw new AssertionError("Should be disconnected");
            notifyCollectorsOfDisconnection();
        }
    }

    private Packet parseFeatures(Element packet) throws Exception {
        for(Element node: XmlUtil.getChildElements(packet)) {
            if(node.getLocalName().equals("register")) {
                connection.getAccountManager().setSupportsAccountCreation(true);
            }
        }

        return new ReceivedPacket(packet);
    }

    private void notifyCollectorsOfDisconnection() {
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