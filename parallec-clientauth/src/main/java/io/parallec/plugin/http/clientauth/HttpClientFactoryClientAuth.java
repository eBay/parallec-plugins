/*  
Copyright [2013-2015] eBay Software Foundation
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
package io.parallec.plugin.http.clientauth;


import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.SslContext;
import io.parallec.core.config.ParallecGlobalConfig;
import io.parallec.core.util.PcFileNetworkIoUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.AsyncHttpClientConfig;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClientConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Async http client store for SSL Client Auth ready.
 * 
 * @author Yuanteng (Jeff) Pei
 * 
 */
public final class HttpClientFactoryClientAuth {

    /** The fast client. */
    private AsyncHttpClient fastClient;

    /** The slow client. */
    private AsyncHttpClient slowClient;

    /** The is closed. */
    private AtomicBoolean isClosed = new AtomicBoolean(false);

    /** The logger. */
    private static Logger logger = LoggerFactory
            .getLogger(HttpClientFactoryClientAuth.class);

    /** The ssl context. */
    private SslContext sslContext;

    /**
     * Stop.
     */
    public void stop() {
        try {
            fastClient.close();
            slowClient.close();
        } catch (IOException ex) {

            logger.error("error stop", ex);
        }
    }

    /**
     * Instantiates a new http client factory client auth.
     *
     * @param privKeyPasshraseFilePath
     *            the priv key passhrase file path
     * @param keystoreFilePath
     *            the keystore file path
     * @param algorithm
     *            the algorithm
     * @param verifyServerCert
     *            the verify server cert
     */
    public HttpClientFactoryClientAuth(String privKeyPasshraseFilePath,
            String keystoreFilePath, String algorithm, boolean verifyServerCert) {
        AsyncHttpClient fastClient = null;
        AsyncHttpClient slowClient = null;
        try {

            if (!PcFileNetworkIoUtils.isFileExist(privKeyPasshraseFilePath)) {
                logger.error("private key pass file does not exist on "
                        + privKeyPasshraseFilePath
                        + ". Cannot load the client auth client. "
                        + "Please prepare the private key pass file and put it in the path and try again.");
                return;
            }

            if (!PcFileNetworkIoUtils.isFileExist(keystoreFilePath)) {
                logger.error("keystore file does not exist on "
                        + keystoreFilePath
                        + ". Cannot load the client auth client. "
                        + "Please prepare the keystore file and put it in the path and try again.");
                return;
            }

            initCertificateVerification(privKeyPasshraseFilePath,
                    keystoreFilePath, algorithm, verifyServerCert);

            // create and configure async http client

            AsyncHttpClientConfig configFastClient = new DefaultAsyncHttpClientConfig.Builder()
                    .setSslContext(sslContext)
                    .setConnectTimeout(
                            ParallecGlobalConfig.ningFastClientConnectionTimeoutMillis)
                    .setRequestTimeout(
                            ParallecGlobalConfig.ningFastClientConnectionTimeoutMillis)
                    .build();

            logger.info(
                    "FastClient Client Auth: ningFastClientConnectionTimeoutMillis: {}",
                    ParallecGlobalConfig.ningFastClientConnectionTimeoutMillis);
            logger.info(
                    "FastClient Client Auth: ningFastClientRequestTimeoutMillis: {}",
                    ParallecGlobalConfig.ningFastClientRequestTimeoutMillis);

            fastClient = new DefaultAsyncHttpClient(configFastClient);

            
            AsyncHttpClientConfig configSlowClient = new DefaultAsyncHttpClientConfig.Builder()
            .setSslContext(sslContext)
            .setConnectTimeout(ParallecGlobalConfig.ningSlowClientConnectionTimeoutMillis)
            .setRequestTimeout(ParallecGlobalConfig.ningSlowClientRequestTimeoutMillis)
            .build();
             slowClient = new DefaultAsyncHttpClient(configSlowClient);

        } catch (Exception e) {
            logger.error("ERROR IN AsyncHttpClientFactorySafe "
                    + e.getLocalizedMessage() + " cause: " + e.getCause());
        }

        this.fastClient = fastClient;
        this.slowClient = slowClient;
    }

    /**
     * Close clients.
     */
    public void closeClients() {
        try {
            slowClient.close();
            fastClient.close();
        } catch (IOException e) {
            logger.error("error close", e);
        }

        isClosed.set(true);
    }

    /**
     * Gets the fast client.
     *
     * @return the fast client
     */
    public AsyncHttpClient getFastClient() {
        return fastClient;
    }

    /**
     * Gets the slow client.
     *
     * @return the slow client
     */
    public AsyncHttpClient getSlowClient() {
        return slowClient;
    }

    /**
     * http://people.apache.org/~simonetripodi/ahc/ssl.html generate JKS:
     * http://venkateshragi.blogspot.com/2013/04/two-way-ssl-using-curl.html
     * openssl pkcs12 -export -out serverkeystore.pkcs12 -in servercert.pem
     * -inkey serverprivatekey.pem keytool -importkeystore -srckeystore
     * serverkeystore.pkcs12 -srcstoretype PKCS12 -destkeystore keystore.jks
     * -deststoretype JKS
     * 
     * The JKS has the client cert/ client key; and the cert of the server.
     *
     * @param privKeyFilePath
     *            the priv key file path
     * @param keystoreFilePath
     *            the keystore file path
     * @param algorithm
     *            the algorithm
     * @param verifyServerCert
     *            the verify server cert
     */
    public void initCertificateVerification(String privKeyFilePath,
            String keystoreFilePath, String algorithm, boolean verifyServerCert) {

        InputStream keyStoreStream = null;
        try {

            /**
             * load certs
             */
            String phrase = PcFileNetworkIoUtils
                    .readFileContentToString(privKeyFilePath);
            phrase = phrase.trim();
            logger.info("loaded private key pass successfully...");
            keyStoreStream = PcFileNetworkIoUtils
                    .readFileToInputStream(keystoreFilePath);
            char[] keyStorePassword = phrase.toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(keyStoreStream, keyStorePassword);
            keyStoreStream.close();
            char[] certificatePassword = phrase.toCharArray();
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");

            kmf.init(ks, certificatePassword);

            KeyManager[] keyManagers = kmf.getKeyManagers();
            SecureRandom secureRandom = new SecureRandom();

            TrustManager[] trustManager = null;

            if (verifyServerCert) {
                TrustManagerFactory trustManagers = TrustManagerFactory
                        .getInstance("SunX509");
                trustManagers.init(ks);
                trustManager = trustManagers.getTrustManagers();

            } else {
                // Install the all-trusting trust manager
                trustManager = new TrustManager[] { new CustomTrustManager() };
            }

            SSLContext sslContextJdk = SSLContext.getInstance(algorithm);
            sslContextJdk.init(keyManagers, trustManager, secureRandom);

            sslContext =  new JdkSslContext(sslContextJdk, true, ClientAuth.REQUIRE);
            
            // not verify the host name for the server cert.
            final HostnameVerifier verifier = new HostnameVerifier() {
                @Override
                public boolean verify(final String hostname,
                        final SSLSession session) {
                    return true;
                }
            };
            HttpsURLConnection.setDefaultHostnameVerifier(verifier);

        } catch (IOException t) {
            logger.error("fail IO Exception when trying to read the files" + t);

        } catch (Throwable t) {
            logger.error("fail" + t);

        } finally {
            if (keyStoreStream != null) {
                try {
                    keyStoreStream.close();
                } catch (IOException e) {
                    logger.error("io exception", e);
                }
            }
        }

    }// end func

    /**
     * class CustomTrustManager.
     */
    public static class CustomTrustManager implements X509TrustManager {

        /**
         * Gets the accepted issuers.
         *
         * @return certificate.
         */
        public X509Certificate[] getAcceptedIssuers() {
            return (X509Certificate[]) null;
        }

        /*
         * (non-Javadoc)
         * 
         * @see
         * javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert
         * .X509Certificate[], java.lang.String)
         */
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        /*
         * (non-Javadoc)
         * 
         * @see
         * javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert
         * .X509Certificate[], java.lang.String)
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }

    }// end inner class

}// end class