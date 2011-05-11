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
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.harmony.javax.security.auth.callback.Callback;
import org.apache.harmony.javax.security.auth.callback.PasswordCallback;

/**
 * An SSLSocketFactory with associated ServerTrustManager.  This allows verifying
 * certificates and retrieving details about certificate failures.
 */
public class XMPPSSLSocketFactory {
    private SSLSocketFactory socketFactory;

    public SSLSocketFactory getSocketFactory() { return socketFactory; }

    /** If at least one insecure connection has been created with this factory,
     * return a CertificateExceptionDetail.  If all connections have been secure,
     * return null. */
    public ServerTrustManager.CertificateExceptionDetail getSeenInsecureConnection() { return seenInsecureConnection; } 
    public ServerTrustManager.CertificateExceptionDetail seenInsecureConnection = null;

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

        socketFactory = context.getSocketFactory();
    }

    /** @return true if TLS is available. */
    public boolean isAvailable() {
        return socketFactory != null;
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
