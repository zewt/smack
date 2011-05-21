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

package org.jivesoftware.smack;

import org.jivesoftware.smack.filter.PacketIDFilter;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.test.SmackTestCase;

public class PacketCollectorTest extends SmackTestCase {
    public PacketCollectorTest(String name) {
        super(name);
    }

    /**
     * Test basic packet collector functionality.
     */
    public void testBasicCollector() throws Exception {
        Message msg = new Message(getConnection(0).getUser(), Message.Type.normal);
        PacketCollector<Message> coll = getConnection(0).createPacketCollector(new PacketIDFilter(msg), Message.class);

        getConnection(1).sendPacket(msg);

        Message receivedMsg = coll.getResult(0);
        assertEquals(receivedMsg.getPacketID(), msg.getPacketID());

        coll.cancel();
    }

    /**
     * Verify that the correct exception is thrown when a packet is received of an
     * unexpected type.
     */
    public void testCollectorTypeMismatch() throws Exception {
        Message msg = new Message(getConnection(0).getUser(), Message.Type.normal);
        PacketCollector<IQ> coll = getConnection(0).createPacketCollector(new PacketIDFilter(msg), IQ.class);

        try {
            getConnection(1).sendPacket(msg);
            coll.getResult(0);
        } catch(XMPPException e) {
            if(!e.getMessage().contains("Unexpected packet type received"))
                fail("Unexpected exception: " + e);
            return;
        } finally {
            coll.cancel();
        }
        fail("Expected XMPPException");
    }

    /**
     * Verify that an exception is thrown by a PacketCollect if the connection is lost
     * before the collector was created. 
     */
    public void testEarlyDisconnection() throws Exception {
        getConnection(0).disconnect();
        Message msg = new Message(getConnection(0).getUser(), Message.Type.normal);
        PacketCollector<IQ> coll = getConnection(0).createPacketCollector(new PacketIDFilter(msg), IQ.class);

        try {
            getConnection(1).sendPacket(msg);
            coll.getResult(0);
        } catch(XMPPException e) {
            if(!e.getMessage().contains("Connection lost"))
                fail("Unexpected exception: " + e);
            return;
        } finally {
            coll.cancel();
        }
        fail("Expected XMPPException");
    }

    /**
     * Verify that an exception is thrown by a PacketCollect if the connection is lost
     * after the collector was created. 
     */
    public void testLateDisconnection() throws Exception {
        Message msg = new Message(getConnection(0).getUser(), Message.Type.normal);
        PacketCollector<IQ> coll = getConnection(0).createPacketCollector(new PacketIDFilter(msg), IQ.class);

        try {
            getConnection(1).sendPacket(msg);
            getConnection(0).disconnect();

            coll.getResult(0);
        } catch(XMPPException e) {
            if(!e.getMessage().contains("Connection lost"))
                fail("Unexpected exception: " + e);
            return;
        } finally {
            coll.cancel();
        }
        fail("Expected XMPPException");
    }

    /**
     * Verify timeout exceptions 
     */
    public void testTimeout() throws Exception {
        Message msg = new Message(getConnection(0).getUser(), Message.Type.normal);
        PacketCollector<IQ> coll = getConnection(0).createPacketCollector(new PacketIDFilter(msg), IQ.class);

        try {
            // Don't send any packet, so getResult() times out.
            // getConnection(1).sendPacket(msg);
            
            coll.getResult(100);
        } catch(XMPPException e) {
            if(!e.getMessage().contains("Response timed out"))
                fail("Unexpected exception: " + e);
            return;
        } finally {
            coll.cancel();
        }
        fail("Expected XMPPException");
    }
    
    /**
     * Verify that an exception is thrown by a PacketCollect if the connection is lost
     * while waiting. 
     */
    public void testAsyncDisconnection() throws Exception {
        Message msg = new Message(getConnection(0).getUser(), Message.Type.normal);
        PacketCollector<IQ> coll = getConnection(0).createPacketCollector(new PacketIDFilter(msg), IQ.class);

        Thread thread = new Thread(new Runnable() {
            public void run() {
                try {
                    Thread.sleep(500);
                    getConnection(0).disconnect();
                } catch(InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        thread.setName("Disconnection thread");
        thread.start();
        
        try {
            // Don't send any packet, so getResult() blocks.
            // getConnection(1).sendPacket(msg);
            
            coll.getResult(1500);
        } catch(XMPPException e) {
            if(!e.getMessage().contains("Connection lost"))
                fail("Unexpected exception: " + e);
            return;
        } finally {
            coll.cancel();
            thread.join();
        }
        fail("Expected XMPPException");
    }
    
    protected int getMaxConnections() {
        return 2;
    }
}
