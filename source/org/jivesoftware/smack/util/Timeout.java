/**
 * $RCSfile$
 * $Revision: 11616 $
 * $Date: 2010-02-09 07:40:11 -0500 (Tue, 09 Feb 2010) $
 *
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

package org.jivesoftware.smack.util;

/** A trivial timeout class, used primarily for tests. */
public class Timeout {
    long endTime = System.currentTimeMillis();

    public Timeout(long ms) { set(ms); }
    
    /** Reset the timer to expire ms in the future. */
    public void set(long ms) {
        endTime = System.currentTimeMillis() + ms;
    }

    /** Return true if this timer has expired. */
    public boolean expired() {
        return System.currentTimeMillis() >= endTime;
    }
};
