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

import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.XMPPError;

import java.util.LinkedList;

/**
 * Provides a mechanism to collect packets into a result queue that pass a
 * specified filter. The collector lets you perform blocking and polling
 * operations on the result queue. So, a PacketCollector is more suitable to
 * use than a {@link PacketListener} when you need to wait for a specific
 * result.<p>
 *
 * Each packet collector will queue up to 2^16 packets for processing before
 * older packets are automatically dropped.
 *
 * @see Connection#createPacketCollector(PacketFilter)
 * @author Matt Tucker
 */
public class PacketCollector<T extends Packet> {

    /**
     * Max number of packets that any one collector can hold. After the max is
     * reached, older packets will be automatically dropped from the queue as
     * new packets are added.
     */
    private static final int MAX_PACKETS = 65536;

    private PacketFilter packetFilter;
    private LinkedList<Packet> resultQueue;
    private Connection connection;
    private boolean cancelled = false;
    private Class<T> packetClass;

    /**
     * Creates a new packet collector. If the packet filter is <tt>null</tt>, then
     * all packets will match this collector.
     * <p>
     * If cls is null, calls to getResult will not be typesafe.  When created using
     * connection.createPacketCollector(filter, cls), cls will be specified.
     * <p>
     * See also {@link #PacketCollector(Connection, PacketFilter)}.
     *
     * @param connection the connection the collector is tied to.
     * @param packetFilter determines which packets will be returned by this collector.
     * @param cls the packet type to return
     */
    protected PacketCollector(Connection connection, PacketFilter packetFilter, Class<T> cls) {
        if (connection == null)
            throw new IllegalArgumentException("connection may not be null");
        if (cls == null)
            throw new IllegalArgumentException("cls may not be null");

        this.connection = connection;
        this.packetFilter = packetFilter;
        this.resultQueue = new LinkedList<Packet>();
        this.packetClass = cls;
    }

    /**
     * Explicitly cancels the packet collector so that no more results are
     * queued up. Once a packet collector has been cancelled, it cannot be
     * re-enabled. Instead, a new packet collector must be created.
     */
    public void cancel() {
        // If the packet collector has already been cancelled, do nothing.
        if (!cancelled) {
            cancelled = true;
            connection.removePacketCollector(this);
        }
    }

    /**
     * Returns the packet filter associated with this packet collector. The packet
     * filter is used to determine what packets are queued as results.
     *
     * @return the packet filter.
     */
    public PacketFilter getPacketFilter() {
        return packetFilter;
    }

    /**
     * Polls to see if a packet is currently available and returns it, or
     * immediately returns <tt>null</tt> if no packets are currently in the
     * result queue.
     * <p>
     * If a packet is available, but of a mismatched packet type, <tt>null</tt> is returned.
     * <p>
     * @return the next packet result, or <tt>null</tt> if there are no more
     *      results.
     */
    public synchronized T pollResult() {
        if (resultQueue.isEmpty()) {
            return null;
        }

        Packet packet = resultQueue.removeLast();
        try {
            return castToType(packet);
        } catch(XMPPException e) {
            return null;
        }
    }

    /**
     * Returns the next available packet. The method call will block (not return)
     * until a packet is available.
     *
     * @return the next available packet.
     * @deprecated see {@link #getResult(long)}
     */
    public synchronized Packet nextResult() {
        // Wait indefinitely until there is a result to return.
        while (resultQueue.isEmpty()) {
            try {
                wait();
            }
            catch (InterruptedException ie) {
                // Ignore.
            }
        }
        return resultQueue.removeLast();
    }

    /**
     * Returns the next available packet. The method call will block (not return)
     * until a packet is available or the <tt>timeout</tt> has elapased. If the
     * timeout elapses without a result, <tt>null</tt> will be returned.
     *
     * @param timeout the amount of time to wait for the next packet (in milleseconds).
     * @return the next available packet.
     * @deprecated see {@link #getResult(long)}
     */
    public synchronized Packet nextResult(long timeout) {
        try {
            return getResult(timeout);
        } catch(XMPPException e) {
            return null;
        }
    }

    /**
     * Returns the next available packet. The method call will block until a packet
     * is available or <tt>timeout</tt> has elapased. If the timeout elapses without
     * a result, <tt>XMPPException</tt> will be thrown.
     * <p>
     * If timeout is 0, the default timeout is used.
     * <p>
     * If the connection is closed before a packet is received, XMPPException is
     * thrown.
     * <p>
     * @param timeout the amount of time to wait for the next packet, in milliseconds
     * @return the next available packet
     * @throws XMPPException if the timeout expires, or if the returned packet is not
     * compatible with the type of this PacketCollector
     */
    public synchronized T getResult(long timeout) throws XMPPException {
        if(cancelled)
            throw new IllegalStateException("getResult called on a cancelled PacketCollector");

        if(timeout == 0)
            timeout = SmackConfiguration.getPacketReplyTimeout();

        // Wait up to the specified amount of time for a result.
        long waitUntil = System.currentTimeMillis() + timeout;
        try {
            // Keep waiting until the specified amount of time has elapsed, or
            // a packet is available to return.
            while (true) {
                // Check the connection first.  This guarantees that if a thread
                // calls connection.disconnect() and immediately calls getResult(),
                // we deterministically throw here, whether messages are waiting or
                // not.
                if(!connection.isConnected())
                    throw new XMPPException("Connection lost");

                if(!resultQueue.isEmpty()) {
                    return castToType(resultQueue.removeLast());
                }

                long waitTime = waitUntil - System.currentTimeMillis();
                if (waitTime <= 0)
                    throw new XMPPException("Response timed out", XMPPError.Condition.request_timeout);

                wait(waitTime);
            }
        }
        catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new XMPPException("Thread interrupted", ie);
        }
    }

    /**
     * Return the result of a single call to {@link #getResult}, and {@link #cancel} the
     * collector.  The collector will be cancelled whether a packet is returned or an
     * exception is thrown.
     */
    public T getOnlyResult(long timeout) throws XMPPException {
        try {
            return getResult(timeout);
        } finally {
            cancel();
        }
    }

    /**
     * Processes a packet to see if it meets the criteria for this packet collector.
     * If so, the packet is added to the result queue.
     *
     * @param packet the packet to process.
     */
    protected synchronized void processPacket(Packet packet) {
        if (packet == null) {
            return;
        }
        if (packetFilter == null || packetFilter.accept(packet)) {
            // If the max number of packets has been reached, remove the oldest one.
            if (resultQueue.size() == MAX_PACKETS) {
                resultQueue.removeLast();
            }
            // Add the new packet.
            resultQueue.addFirst(packet);
            // Notify waiting threads a result is available.
            notifyAll();
        }
    }

    /**
     * This is called by PacketReader when the connection has been lost.
     * <p>
     * Disconnection tests against connection.isConnected().  As we're not
     * synchronized against connection, isConnected() must already return
     * false before this function is called in order to prevent race conditions.
     */
    public synchronized void connectionLost() {
        // Wake up anyone waiting for a packet.
        notifyAll();
    }

    /**
     * Cast the given packet to the type of this PacketCollector.  Throws
     * XMPPException if the packet is of an incorrect type.
     */
    private T castToType(Packet packet) throws XMPPException {
        try {
            return packetClass.cast(packet);
        }
        catch(ClassCastException e) {
            throw new XMPPException("Unexpected packet type received (got " + packet.getClass().getName() + ")");
        }
    }
}
