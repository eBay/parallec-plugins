<a href="http://www.parallec.io"><img alt="Parallec-logo" src="http://www.parallec.io/images/parallec-logo.png" width="325"></a>

# Parallec Plugins

## parallec-clientauth

SSL Client Authentication Plug-in for [Parallec](http://www.parallec.io). One line to help you set the SSL context for Client Authentication. Import it and add the jks file and the text file containing the private key pass to userdata folder.
You will be good to go with. You may also provide customized absolute or relative path to load the keystore. 

###Maven/Gradle Import
Along with your parallec import, also add: 
#####Maven

```xml
<dependency>
	<groupId>io.parallec</groupId>
	<artifactId>parallec-plugin-http-clientauth</artifactId>
	<version>0.9.0</version>
</dependency>
```	

#####Gradle

```xml
compile 'io.parallec:parallec-plugin-http-clientauth:0.9.0'
```


##How to use

1. Add the .jks file and rename it to "keystore.jks"  ; Add a text file only containing the passphrase for the private key and rename it to "keypass";  Put both file under userdata folder in your project directory

2. Insert this line after initializing the ParallelClient instance before using it: 

```java
ParallelClient pc= new ParallelClient();
ClientAuthAdaptor.getInstance().enableClientAuth(pc);
```

If need to overload the path, please call the same function with additional path parameters (absolute or relative path to project).

```java
ParallelClient pc= new ParallelClient();
ClientAuthAdaptor.getInstance().enableClientAuth(parallec,
	    		"/Users/yourname/git/parallec/userdata/keypass",
	    		"/Users/yourname/git/parallec/userdata/keystore.jks"
	    		); // mutual auth with customized path
```
####Change Algorithm

Default algorithm is "TLS". Review available algorithms [here](http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SSLContext).

The same API with different arguments can change the algorithm too. Details please refer to the javadoc.

```java
enableClientAuth(ParallelClient pc, String algorithm) 


```


```java
enableClientAuth(ParallelClient pc,
            String privKeyPasshraseFilePath, String keystoreFilePath,
            String algorithm, boolean verifyServerCert)

```
###Shutdown HttpClientFactory

The enableClientAuth will automatic create the Async HTTP Client factory which loads the key pairs.  If need to close the clients, call 

	ClientAuthAdaptor.getInstance().shutdown();

For more details please check: src/main/java/io/parallec/plugin/http/clientauth/ClientAuthAdaptor.java


###Versions

* The latest production-ready version is `0.9.x`, where we use in production.
* **On async-http-client 2.x** The Parallec plugin version using more up-to-date `async-http-client` (currently using AHC version `2.0.15`) is `0.20.0-SNAPSHOT`. This version **requires JDK8** due to AHC 2.x and should be used with the parallec-core with the same version `0.20.0-SNAPSHOT`, details please check [#37](https://github.com/eBay/parallec/issues/37).

## Author and Contributors
#### Original Author
Yuanteng (Jeff) Pei

#### Contributors

Your name here

Thanks for trying Parallec.io. Please submit a git issue for any questions you have.


## Licenses

Code licensed under Apache License v2.0

© 2015 eBay Software Foundation
