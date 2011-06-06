/**
 * Copyright 2003-2007 Jive Software.
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

package org.jivesoftware.smack;

import java.lang.reflect.Constructor;
import java.util.Vector;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.jivesoftware.smack.XMPPStream.ConnectData;
import org.jivesoftware.smack.util.ObservableReader.ReadEvent;
import org.jivesoftware.smack.util.ObservableWriter.WriteEvent;
import org.jivesoftware.smack.util.ThreadUtil;

class ConnectionOpener
{
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition cond = lock.newCondition();
    
    private final ConnectionConfiguration config;
    
    /** The stream we're currently attempting to open, if any.  Threads other
     *  than the one calling connect() must lock to access this.  This can only
     *  be set or cleared by connect(), and only while locked. */
    private XMPPStream stream;
    
    /** A connect() call is in progress. */
    private boolean running = false;

    /** cancel() has been called, and cancel() is waiting for running to be cleared, to indicate
     *  that connect() has returned. */
    private boolean cancelling = false;

    ConnectionOpener(ConnectionConfiguration config) {
        this.config = config;
    }

    /** Create and return a new {@link XMPPStream}. */
    private XMPPStream createDataStream(Class<? extends XMPPStream> transport) {
        // Create an instance of this transport.
        Constructor<? extends XMPPStream> constructor;
        try {
            constructor = transport.getConstructor(ConnectionConfiguration.class);
            return constructor.newInstance(config);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void throwIfCancelled() throws XMPPException {
        assertLocked();
        if(cancelling)
            throw new XMPPException("Connection cancelled");
    }
    
    /** Look up the ConnectionData for the given transport and configuration. */
    private ConnectData lookupConnectionData(Class<? extends XMPPStream> transport) throws XMPPException {
        assertNotLocked();

        lock.lock();
        try {
            throwIfCancelled();
            stream = createDataStream(transport);
        } finally {
            lock.unlock();
        }

        // Schedule a timeout.
        int waitTime = SmackConfiguration.getPacketReplyTimeout();
        TimeoutThread timeoutThread = new TimeoutThread("Connection timeout thread", waitTime, new Runnable() {
            public void run() { cancelInternal(); }
        });

        try {
            try {
                // It's safe to call this unlocked.  Other threads are not allowed to change stream.
                return stream.getConnectData();
            } finally {
                timeoutThread.cancel();

                lock.lock();
                try {
                    stream = null;
                } finally {
                    lock.unlock();
                }
            }
        } catch(XMPPException e) {
            if(timeoutThread.executed)
                throw new XMPPException("Connection failed. No response from server.");
            else
                throw e;
        }
    }

    static private class TimeoutThread extends Thread {
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
    

    /**
     * Initializes the connection, opening an XMPP stream to the server.
     *
     * @throws XMPPException if establishing a connection to the server fails.
     */
    private void beginConnection(ConnectData connectData, int attempt) throws XMPPException {
        assertNotLocked();

        // Schedule a timeout.
        int waitTime = SmackConfiguration.getPacketReplyTimeout();
        TimeoutThread timeoutThread = new TimeoutThread("Connection timeout thread", waitTime, new Runnable() {
            public void run() { cancelInternal(); }
        });

        try {
            try {
                // It's safe to call this unlocked.  Other threads are not allowed to change stream.
                stream.initializeConnection(connectData, attempt);
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


    private void assertNotLocked() {
        if(lock.isHeldByCurrentThread())
            throw new RuntimeException("Lock should not be held");
    }

    private void assertLocked() {
        if(!lock.isHeldByCurrentThread())
            throw new RuntimeException("Lock should be held");
    }
    
    private XMPPStream performConnect(ReadEvent readEvent, WriteEvent writeEvent) throws XMPPException {
        assertNotLocked();

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
            ConnectData connectData;
            try {
                connectData = lookupConnectionData(transport);
            } catch(XMPPException e) {
                if(cancelling)
                    throw e;

                continue;
            }

            // If no hosts were discovered for this transport, move on to the next.
            if(connectData.connectionAttempts() == 0)
                continue;

            // Attempt to connect using this transport.  If the transport discovers more
            // than one server to connect to, try each in order.  Note that timeouts are
            // per-server.
            for(int i = 0; i < connectData.connectionAttempts(); ++i) {
                if(stream != null)
                    throw new AssertionError("stream should be null");

                lock.lock();
                try {
                    throwIfCancelled();
                    stream = createDataStream(transport);
                    stream.setReadWriteEvents(readEvent, writeEvent);
                } finally {
                    lock.unlock();
                }

                try {
                    beginConnection(connectData, i);
                    return stream;
                } catch(XMPPException e) {
                    lock.lock();
                    try {
                        stream = null;
                    } finally {
                        lock.unlock();
                    }

                    if(cancelling)
                        throw e;

                    // On failure, connectUsingConfigurationAttempt always clears stream.
                    if(stream != null)
                        throw new AssertionError("connectUsingConfigurationAttempt failed, but left stream set");

                    firstFailure = e;
                }
            }
        }

        // We didn't connect.  Report the first failure other than remote_server_not_found
        // as the error.
        throw firstFailure;
    }
    
    /**
     * Connect to the configured server, returning the resulting XMPPStream.
     * This function may only be called once per instance.
     * <p>
     * {@link cancel} may be called asynchronously to cancel the connection.
     */
    public XMPPStream connect(ReadEvent readEvent, WriteEvent writeEvent) throws XMPPException {
        assertNotLocked();

        lock.lock();
        try {
            throwIfCancelled();            
            running = true;
        } finally {
            lock.unlock();
        }
        
        try {
            return performConnect(readEvent, writeEvent);
        } finally {
            lock.lock();
            try {
                running = false;
                cond.signalAll();
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * Asynchronously cancel any current or future call to {@link #connect}.
     * <p>
     * The only difference between {@link #cancel} and {@code cancelInternal} is that
     * {@code cancel} waits for the connect() call to complete.   This call is used
     * from our timeout threads; we can't wait for connect() to complete from there,
     * because connect() joins the timeout threads.
     */
    private void cancelInternal()
    {
        // This function must be able to deal with being called multiple times in
        // parallel, as well.  The user can call this, and our TimeoutThreads can
        // also call it.
        assertNotLocked();
        lock.lock();
        try {
            cancelling = true;
            if(stream != null)
                stream.disconnect();
        } finally {
            lock.unlock();
        }
    }
    
    /** Asynchronously cancel any current or future call to {@link #connect}. */
    public void cancel()
    {
        // This function must be able to deal with being called multiple times in
        // parallel, as well.  The user can call this, and our TimeoutThreads can
        // also call it.
        assertNotLocked();
        cancelInternal();

        // If connect() is running, wait for it to cancel.
        lock.lock();
        try {
            while(running)
                ThreadUtil.uninterruptibleWait(cond);
        } finally {
            lock.unlock();
        }
    }
}
