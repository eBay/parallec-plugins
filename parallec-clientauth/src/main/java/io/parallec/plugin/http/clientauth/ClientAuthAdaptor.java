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

import io.parallec.core.ParallelClient;
import io.parallec.core.config.ParallecGlobalConfig;
import io.parallec.core.resources.HttpClientType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: Auto-generated Javadoc
/**
 * client auth adaptor ready for use. put the private key pass file to
 * userdata/keypass put the keystore file to userdata/keystore.jks
 * 
 * call ClientAuthAdaptor.changeDefaultToClientAuthClient(parallelClient);
 * 
 * to enable mutual auth.
 * 
 * @author Yuanteng Jeff Pei
 *
 */
public class ClientAuthAdaptor {

    /** The logger. */
    private static Logger logger = LoggerFactory
            .getLogger(ClientAuthAdaptor.class);

    /** The private key pass phrase file path default. */
    public String privKeyPassPhraseFilePathDefault = ParallecGlobalConfig.userDataFolderWithSlash
            + "keypass";

    /** The keystore file path default. */
    public String keystoreFilePathDefault = ParallecGlobalConfig.userDataFolderWithSlash
            + "keystore.jks";

    /** The algorithm default. Check protocol at 
     * http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SSLContext
     *  */
    public static String algorithmDefault = "TLS";

    /** The verify server cert default. */
    public static boolean verifyServerCertDefault = false;

    /** The Constant instance. */
    private final static ClientAuthAdaptor instance = new ClientAuthAdaptor();

    /**
     * Gets the single instance of ClientAuthAdaptor.
     *
     * @return single instance of ClientAuthAdaptor
     */
    public static ClientAuthAdaptor getInstance() {
        return instance;
    }

    /**
     * Instantiates a new client auth adaptor.
     */
    private ClientAuthAdaptor() {
    }

    /** The factory. */
    public HttpClientFactoryClientAuth factory = null;

    /**
     * Enable client auth with all default.
     *
     * @param pc the pc
     */
    public void enableClientAuth(ParallelClient pc) {
        enableClientAuth(pc, privKeyPassPhraseFilePathDefault,
                keystoreFilePathDefault, algorithmDefault,
                verifyServerCertDefault);
    }

    /**
     * Enable client auth.
     * just change the algorithm, all other are default
     *
     * @param pc the pc
     * @param algorithm the algorithm
     */
    public void enableClientAuth(ParallelClient pc, String algorithm) {
        enableClientAuth(pc, privKeyPassPhraseFilePathDefault,
                keystoreFilePathDefault, algorithm,
                verifyServerCertDefault);
    }

    /**
     * Enable client auth, with default algorithm/verifyServerCert.
     *
     * @param pc the pc
     * @param privKeyPasshraseFilePath the priv key passhrase file path
     * @param keystoreFilePath the keystore file path
     */
    public void enableClientAuth(ParallelClient pc,
            String privKeyPasshraseFilePath, String keystoreFilePath) {
        enableClientAuth(pc, privKeyPasshraseFilePath, keystoreFilePath,
                algorithmDefault, verifyServerCertDefault);
    }

    /**
     * Enable client auth, with verifyServerCertDefault.
     *
     * @param pc the pc
     * @param privKeyPasshraseFilePath the priv key passhrase file path
     * @param keystoreFilePath the keystore file path
     * @param algorithm the algorithm
     */
    public void enableClientAuth(ParallelClient pc,
            String privKeyPasshraseFilePath, String keystoreFilePath,
            String algorithm) {
        enableClientAuth(pc, privKeyPasshraseFilePath, keystoreFilePath,
                algorithm, verifyServerCertDefault);
    }

    /**
     * Enable client auth.
     *
     * @param pc            the ParallelClient
     * @param privKeyPasshraseFilePath            the priv key passhrase file path
     * @param keystoreFilePath            the keystore file path
     * @param algorithm the algorithm
     * @param verifyServerCert the verify server cert
     */
    public void enableClientAuth(ParallelClient pc,
            String privKeyPasshraseFilePath, String keystoreFilePath,
            String algorithm, boolean verifyServerCert) {

        if (factory == null) {
            factory = new HttpClientFactoryClientAuth(privKeyPasshraseFilePath,
                    keystoreFilePath, algorithm, verifyServerCert);
        } else {
            logger.debug("factory is already initialized. will NO OP. "
                    + "call reset() to close the current clients and then try again.");
            return;
        }
        pc.setCustomClientFast(factory.getFastClient());
        pc.setCustomClientSlow(factory.getSlowClient());
        pc.setHttpClientTypeCurrentDefault(HttpClientType.CUSTOM_FAST);

    }

    /**
     * close the AHC clients and set this factory as null.
     */
    public void shutdown() {

        if (factory != null) {
            factory.closeClients();
            factory = null;
            logger.info("factory clients have been closed and set as null. ready to init again ");
        } else {
            logger.debug("factory is not initialized. will NO OP. ");
            return;
        }

    }

}
