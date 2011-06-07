/*
 *  Copyright 2011 Glenn Maynard
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.jivesoftware.smack.util.collections;

/** An implementation of the notoriously missing trivial Pair class. */
public class Pair<T, U>
{
    final T t;
    final U u;

    public Pair(T t, U u) { this.t = t; this.u = u; }

    public boolean equals(Object rhs) {
        if(rhs == this)
            return true;
        if(!(rhs instanceof Pair))
            return false;

        Pair rhsPair = (Pair) rhs;
        return t.equals(rhsPair.t) && u.equals(rhsPair.u);
    }

    public int hashCode() {
        return t.hashCode() + u.hashCode();
    }
}
