/**
 * $RCSfile$
 * $Revision: 3306 $
 * $Date: 2006-01-16 14:34:56 -0300 (Mon, 16 Jan 2006) $
 *
 * Copyright 2003-2011 Jive Software, Glenn Maynard.
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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.WeakHashMap;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.harmony.javax.security.auth.callback.Callback;
import org.apache.harmony.javax.security.auth.callback.PasswordCallback;

/**
 * An SSLSocketFactory with associated ServerTrustManager.  This allows verifying
 * certificates and retrieving details about certificate failures.  We also enable
 * support for TLS compression here, if support is available. 
 */
public class XMPPSSLSocketFactory {
    private WrappedSocketFactory socketFactory;

    public SSLSocketFactory getSocketFactory() { return socketFactory; }

    /** Store information about each socket connection.  There's no good way to wrap
     *  an SSLSocket that another class gives to us, so we store these in a WeakHashMap. */
    private class SSLSocketInfo { 
        // If compression is enabled, this contains the compression method used.  If compression
        // is not enabled, this is null.
        String compressionMethod;
    };
    public WeakHashMap<SSLSocket, SSLSocketInfo> map = new WeakHashMap<SSLSocket, SSLSocketInfo>();

    /* A SocketFactory that initializes its returned sockets with our TrustManager. */
    private class WrappedSocketFactory extends SSLSocketFactory {
        SSLSocketFactory wrapped;

        WrappedSocketFactory(SSLSocketFactory factory) {
            this.wrapped = factory;
        }

        public Socket createSocket() throws IOException {
            return initSocket(wrapped.createSocket());
        }

        public Socket createSocket(String host, int port)
        throws IOException, UnknownHostException {
            return initSocket(wrapped.createSocket(host, port));
        }

        public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
        throws IOException, UnknownHostException {
            return initSocket(wrapped.createSocket(host, port, localHost, localPort));
        }

        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            return initSocket(wrapped.createSocket(s, host, port, autoClose));
        }

        // These two calls aren't told the remote host's name, so it's not possible to check
        // certificates.
        public Socket createSocket(InetAddress host, int port) throws IOException {
            return initSocket(wrapped.createSocket(host, port));
        }

        public Socket createSocket(InetAddress address, int port,
                InetAddress localAddress, int localPort) throws IOException {
            return initSocket(wrapped.createSocket(address, port, localAddress, localPort));
        }

        public String[] getDefaultCipherSuites() { return wrapped.getDefaultCipherSuites(); }
        public String[] getSupportedCipherSuites() { return wrapped.getSupportedCipherSuites(); }

        // If host is null, we're connecting directly to an IP address.  We won't be able
        // to verify the host certificate.
        private SSLSocket initSocket(Socket socket) {
            SSLSocket sslSocket = (SSLSocket) socket;

            SSLSocketInfo info = new SSLSocketInfo();
            map.put(sslSocket, info);

            sslSocket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
                public void handshakeCompleted(HandshakeCompletedEvent event) {
                    SSLSocket socket = (SSLSocket) event.getSocket();
                    SSLSocketInfo info = map.get(socket);

                    info.compressionMethod = getCompressionMethod(socket);
                }
            });

            initCompression(sslSocket);

            return sslSocket;
        }

        /** Attempt to request compression on the given socket, if supported by the implementation.
         *  This is supported by org.apache.harmony.xnet.provider.jsse. */
        private void initCompression(SSLSocket socket)
        {
            try {
                Method getSupportedCompressionMethods = socket.getClass().getMethod("getSupportedCompressionMethods");
                Method setEnabledCompressionMethods = socket.getClass().getMethod("setEnabledCompressionMethods", String[].class);

                String[] compressionMethods = (String[]) getSupportedCompressionMethods.invoke(socket);
                setEnabledCompressionMethods.invoke(socket, (Object) compressionMethods);
            } catch (Exception e) {
            }
        }

        /** Return the name of the compression method in use on a socket, or null if none is active. */
        private String getCompressionMethod(SSLSocket socket) {
            try {
                SSLSession session = socket.getSession();
                Method getCompressionMethod = session.getClass().getMethod("getCompressionMethod");
                String compressionMethod = (String) getCompressionMethod.invoke(session);
                if(compressionMethod != null && compressionMethod.equals("NULL"))
                    return null;
                else
                    return compressionMethod;
            } catch (Exception e) {
                return null;
            }
        }
    };

    XMPPSSLSocketFactory(ConnectionConfiguration config, String originalServiceName)
    throws XMPPException
    {
        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");
        } catch (NoSuchAlgorithmException e) {
            // The environment doesn't support TLS.  Clear socketFactory, and
            // isAvailable will return false.
            socketFactory = null;
            e.printStackTrace();
            return;
        }

        getServerTrustManager(context, config, originalServiceName);

        SSLSocketFactory factory = context.getSocketFactory();
        socketFactory = new WrappedSocketFactory(factory);
    }

    /** @return true if TLS is available. */
    public boolean isAvailable() {
        return socketFactory != null;
    }

    /** Return the name of the compression in use on the specified socket, or null if no
     * compression is active. */
    public String getCompressionMethod(SSLSocket socket) {
        return map.get(socket).compressionMethod;
    }

    private static KeyManager[] createKeyManagers(ConnectionConfiguration config)
    throws Exception
    {
        KeyStore ks = null;
        PasswordCallback pcb = null;
        KeyManager[] kms = null;

        if(config.getCallbackHandler() == null)
            return null;
        if(config.getKeystoreType().equals("NONE"))
            return null;

        if(config.getKeystoreType().equals("PKCS11")) {
            try {
                Constructor<?> c = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class);
                String pkcs11Config = "name = SmartCard\nlibrary = "+config.getPKCS11Library();
                ByteArrayInputStream inputStream = new ByteArrayInputStream(pkcs11Config.getBytes());
                Provider p = (Provider)c.newInstance(inputStream);
                Security.addProvider(p);
                ks = KeyStore.getInstance("PKCS11",p);
                pcb = new PasswordCallback("PKCS11 Password: ",false);
                config.getCallbackHandler().handle(new Callback[]{pcb});
                ks.load(null,pcb.getPassword());
            }
            catch (Exception e) {
                ks = null;
                pcb = null;
            }
        }
        else if(config.getKeystoreType().equals("Apple")) {
            ks = KeyStore.getInstance("KeychainStore","Apple");
            ks.load(null, null);
            //pcb = new PasswordCallback("Apple Keychain",false);
            //pcb.setPassword(null);
        }
        else {
            ks = KeyStore.getInstance(config.getKeystoreType());
            try {
                pcb = new PasswordCallback("Keystore Password: ",false);
                config.getCallbackHandler().handle(new Callback[]{pcb});
                ks.load(new FileInputStream(config.getKeystorePath()), pcb.getPassword());
            }
            catch(Exception e) {
                ks = null;
                pcb = null;
            }
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        try {
            if(pcb == null) {
                kmf.init(ks,null);
            } else {
                kmf.init(ks,pcb.getPassword());
                pcb.clearPassword();
            }
            kms = kmf.getKeyManagers();
        } catch (NullPointerException npe) {
            kms = null;
        }
        return kms;
    }

    /**
     * Prepare a ServerTrustManager and initialize the given context with it.  Return
     * the created ServerTrustManager.
     */
    public static ServerTrustManager getServerTrustManager(SSLContext context, ConnectionConfiguration config,
            String serviceName) throws XMPPException
    {
        try {
            KeyManager[] kms = createKeyManagers(config);

            // Verify certificate presented by the server
            ServerTrustManager trustManager = new ServerTrustManager(serviceName, config);
            TrustManager[] trustManagers = new TrustManager[]{trustManager};

            try {
                context.init(kms, trustManagers, new SecureRandom());
            } catch (KeyManagementException e) {
                throw new XMPPException(e);
            }

            return trustManager;
        } catch(RuntimeException e) {
            throw e; // don't catch unchecked exceptions below
        } catch(Exception e) {
            throw new XMPPException("Error creating keystore", e);
        }
    }
};
