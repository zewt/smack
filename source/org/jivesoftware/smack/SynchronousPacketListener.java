/**
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

import org.jivesoftware.smack.packet.Packet;

/**
 * SynchronousPacketListeners are {@link PacketListeners} which are run synchronously
 * when a packet is received.
 * <p>
 * A standard {@link PacketListener} is run asynchronously, and are allowed to make
 * any API call.
 * <p>
 * A SynchronousPacketListener runs synchronously in the packet reader thread.  No
 * further packets will be processed while listeners are running.  This allows handling
 * packet responses in order as they're received.  However, as they block the PacketReader
 * thread, attempting to block on a PacketCollector will cause a deadlock, as no packets
 * are being processed.
 */
public abstract class SynchronousPacketListener implements PacketListener {
}
