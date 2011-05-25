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

package org.jivesoftware.smack.util;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.jivesoftware.smack.XMPPException;

/** Dynamically-loaded interface for java.text.Normalizer(NFKC); it's missing
 *  in non-bleeding-edge versions of Android and we can get by without it. */
class Normalizer {
    private static boolean initialized = false;
    private static Method normalize; // java.text.Normalizer.normalize
    private static Object nfkc; // java.text.Normalizer.Form.NFKC
    private static Object lock = new Object();

    /** Equivalent to {@link java.text.Normalizer#normalize}(seq, Normalizer.Form.NFKC).
     *  If Normalizer is unavailable, returns the sequence unchanged. */
    public static String normalize(CharSequence seq) {
        synchronized(lock) {
            if(!initialized) {
                initialized = true;
                try {
                    initialize("java.text.Normalizer");
                } catch(XMPPException e) {
                    // XXX: warn
                }
            }
        }

        if(normalize == null)
            return seq.toString();

        try {
            return (String) normalize.invoke(null, seq, nfkc);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    private static void initialize(String classPath) throws XMPPException {
        try {
            Class<?> normalizerClass = Class.forName(classPath);
            Class<?> normalizerFormClass = findSubclassByName(normalizerClass, "Form");
            Object[] normalizerConstants = normalizerFormClass.getEnumConstants();

            nfkc = findObjectByValue(normalizerConstants, "NFKC");
            normalize = normalizerClass.getMethod("normalize", CharSequence.class, normalizerFormClass);
        } catch (SecurityException e) {
            throw new XMPPException("Couldn't load java.text.Normalizer", e);
        } catch (NoSuchMethodException e) {
            throw new XMPPException("Couldn't load java.text.Normalizer", e);
        } catch (ClassNotFoundException e) {
            throw new XMPPException("Couldn't load java.text.Normalizer", e);
        }
    }

    static abstract class Impl {
        abstract String normalize(CharSequence seq);
    }

    private static Class<?> findSubclassByName(Class<?> parentClass, String name) throws ClassNotFoundException {
        Class<?>[] subClasses = parentClass.getClasses();
        String searchForName = parentClass.getName() + "$Form";
        for(Class<?> memberClass: subClasses) {
            String s = memberClass.getName();
            if(s.equals(searchForName))
                return memberClass;
        }
        throw new ClassNotFoundException();
    }

    private static Object findObjectByValue(Object[] objects, String s) throws ClassNotFoundException {
        for(Object e: objects) {
            if(e.toString().equals(s))
                return e;
        }
        throw new ClassNotFoundException();
    }
}
