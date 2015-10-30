# parallec-clientauth

SSL Client Authentication Plug-in for Parallec. One line to help you set the SSL context for Client Authentication. Import it and add the jks file and the text file containing the private key pass to userdata folder.
You will be good to go with. You may over provide customized absolute or relative path to load the paths 

###Maven Import
	
```xml
<dependency>
	<groupId>io.parallec</groupId>
	<artifactId>parallec-plugin-http-clientauth</artifactId>
	<version>0.8.12-beta</version>
</dependency>
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

The enableClientAuth will automatic create the Async HTTP Client factory which loaded the key pairs.  If need to close the clients, call 

	ClientAuthAdaptor.getInstance().shutdown();

For more details please check: src/main/java/io/parallec/plugin/http/clientauth/ClientAuthAdaptor.java
