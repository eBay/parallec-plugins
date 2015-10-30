package io.parallec.plugin.http.clientauth;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;


/**
 * Async http client store for SSL Client Auth ready 
 * @author Yuanteng Jeff Pei
 * 
 */
public final class HttpClientFactoryClientAuth {
    
	private AsyncHttpClient fastClient;
	private AsyncHttpClient slowClient;
	private AtomicBoolean isClosed = new AtomicBoolean(false);
	private static Logger logger = LoggerFactory.getLogger(HttpClientFactoryClientAuth.class);
	
	private SSLContext sslContext;

	public void stop() {
		fastClient.close();
		slowClient.close();
	}

	public HttpClientFactoryClientAuth(
	        String privKeyPasshraseFilePath, String keystoreFilePath
	        ,String algorithm, boolean verifyServerCert
	        ) {
		AsyncHttpClient fastClient = null;
		AsyncHttpClient slowClient = null;
		try {
			
			if(!PcFileNetworkIoUtils.isFileExist(privKeyPasshraseFilePath)){
				logger.error("private key pass file does not exist on " + privKeyPasshraseFilePath + ". Cannot load the client auth client. "
						+ "Please prepare the private key pass file and put it in the path and try again."
						);
				return;
			}
			
			if(!PcFileNetworkIoUtils.isFileExist(keystoreFilePath)){
				logger.error("keystore file does not exist on " + keystoreFilePath + ". Cannot load the client auth client. "
						 + "Please prepare the keystore file and put it in the path and try again."
						);
				return;
			}
			
			initCertificateVerification(privKeyPasshraseFilePath, keystoreFilePath
			        ,algorithm,  verifyServerCert);

			// create and configure async http client
			com.ning.http.client.AsyncHttpClientConfig.Builder builderFastClient = new AsyncHttpClientConfig.Builder();
			builderFastClient.setSSLContext(sslContext);
			builderFastClient
					.setConnectionTimeoutInMs(ParallecGlobalConfig.ningFastClientConnectionTimeoutMillis);
			builderFastClient
					.setRequestTimeoutInMs(ParallecGlobalConfig.ningFastClientRequestTimeoutMillis);
			
			logger.info("FastClient Client Auth: ningFastClientConnectionTimeoutMillis: {}", ParallecGlobalConfig.ningFastClientConnectionTimeoutMillis);
			logger.info("FastClient Client Auth: ningFastClientRequestTimeoutMillis: {}", ParallecGlobalConfig.ningFastClientRequestTimeoutMillis);
			
			fastClient = new AsyncHttpClient(builderFastClient.build());
			
			com.ning.http.client.AsyncHttpClientConfig.Builder builderSlowClient = new AsyncHttpClientConfig.Builder();
			builderSlowClient.setSSLContext(sslContext);
			builderSlowClient
					.setConnectionTimeoutInMs(ParallecGlobalConfig.ningSlowClientConnectionTimeoutMillis);
			builderSlowClient
					.setRequestTimeoutInMs(ParallecGlobalConfig.ningSlowClientRequestTimeoutMillis);
			slowClient = new AsyncHttpClient(builderSlowClient.build());
			
			//slowClient = new AsyncHttpClient(new ApacheAsyncHttpProvider(builderSlowClient.build()));
			
		} catch (Exception e) {
			logger.error("ERROR IN AsyncHttpClientFactorySafe "
							+ e.getLocalizedMessage() + " cause: "
							+ e.getCause());
		}

		this.fastClient = fastClient;
		this.slowClient = slowClient;
	}
	
	public void closeClients() {
		slowClient.close();
		fastClient.close();
		
		isClosed.set(true);
	}

	public AsyncHttpClient getFastClient() {
		return fastClient;
	}

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
	 */
	public void initCertificateVerification(
	        String privKeyFilePath, String keystoreFilePath,
	        String algorithm, boolean verifyServerCert
	        ) {

		InputStream keyStoreStream = null;
		try {
			
			/**
			 * load certs
			 */
			String phrase = PcFileNetworkIoUtils.readFileContentToString(privKeyFilePath);
			phrase=phrase.trim();
			logger.info("loaded private key pass successfully..." );
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
			
			if(verifyServerCert){
				TrustManagerFactory trustManagers = TrustManagerFactory
						.getInstance("SunX509");
				trustManagers.init(ks);
				trustManager = trustManagers.getTrustManagers();
				
			}else{
			    // Install the all-trusting trust manager
				trustManager = new TrustManager[] { new
						CustomTrustManager() };
			}

			sslContext = SSLContext.getInstance(algorithm);
			sslContext.init(keyManagers, trustManager, secureRandom);
			
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
		 * @return certificate.
		 */
		public X509Certificate[] getAcceptedIssuers() {
			return (X509Certificate[]) null;
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
		}

	}// end inner class
	
}// end class