package SSLTests;

import com.sinequa.common.Str;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

//TODO: Tests using the external Apache server.
public class SSLTests {
    private CloseableHttpClient httpClient;
    private static final String PROTOCOL = "TLS";
    private static final String JAVA_KEYSTORE = "jks";

    // NOTE: The below variables are used for specific scenarios and are not meant to be changes (hence the 'final' keyword). They're meant to be descriptive of the scenarion in which they are used.
    private static final boolean ONE_WAY_SSL = false; // 1-way SSL does NOT require client certificate authentication in the serverSSLContext.
    private static final boolean TWO_WAY_SSL = true; // 2-way SSL DOES require client certificate authentication in the serverSSLContext.
    private static final SSLContext NO_SSL_CONTEXT = null;
    private static final TrustManager[] NO_SERVER_TRUST_MANAGER = null;
    private static final KeyStore NO_CLIENT_KEYSTORE = null;

    /**
     Scenario: HTTP request to an embedded server with no SSL.
     */
    public void httpRequest_embeddedServer_Returns200OK()
            throws Exception
    {
        final HttpServer server = createLocalTestServer(NO_SSL_CONTEXT, ONE_WAY_SSL);
        server.start();

        httpClient = HttpClients.createDefault();

        String baseUrl = getBaseUrl(server);
        HttpGet getRequest = new HttpGet("http://" + baseUrl + "/echo/this");
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(getRequest);
        }
        finally
        {
            if (httpResponse != null) {
                System.out.println(Str.and("httpRequest_embeddedServer_Returns200OK - Response.Status:\t", httpResponse.getStatusLine()));
                System.out.println(Str.and("httpRequest_embeddedServer_Returns200OK - Response:\t", httpResponse.toString()));

                httpResponse.close();
            }

            httpClient.close();
            server.stop();
        }
    }

    /**
     * Scenario: HTTP request to the external Apache server, which has separate virtual hosts configured to handle clear and secure communication.
     */
    public void httpRequest_externalServer_Returns200OK()
            throws IOException
    {
        CloseableHttpClient client = HttpClients.createMinimal();

        HttpGet getRequest = new HttpGet("http://localhost/");
        CloseableHttpResponse httpResponse = null;
        try
        {
            httpResponse = client.execute(getRequest);
        }
        finally {
            if (httpResponse != null) {
                System.out.println(Str.and("httpRequest_externalServer_Returns200OK - Response.Status:\t", httpResponse.getStatusLine()));
                System.out.println(Str.and("httpRequest_externalServer_Returns200OK - Response:\t", httpResponse.toString()));

                httpResponse.close();
            }

            httpClient.close();
        }
    }

    // 1-WAY SSL TESTS
    /**
     (OLD) Scenario: Client attempts to authenticate Server, but won't be able to because the Server's certificate isn't in the client's default TrustStore and because we did not instantiate our own client TrustStore.
     Scenario: Client and server have an SSL Context for HTTPS, but the server does not validate the client and the client accepts any server.
     */
    public void httpsRequest_embeddedServer_1WaySSL_SSLWithoutAnyValidation_Returns200OK(String SERVER_KEYSTORE, char[] KEYPASS_AND_STOREPASS_VALUE)
            throws CertificateException, KeyStoreException,UnrecoverableKeyException, KeyManagementException, IOException, NoSuchAlgorithmException
    {
        SSLContext serverSSLContext = createServerSSLContext(SERVER_KEYSTORE, NO_SERVER_TRUST_MANAGER, KEYPASS_AND_STOREPASS_VALUE);
        final HttpServer server = createLocalTestServer(serverSSLContext, ONE_WAY_SSL);
        server.start();

        SSLContext clientSSLContext = new SSLContextBuilder().loadTrustMaterial(
                NO_CLIENT_KEYSTORE, // Client does not have a store from which to present its certificate to the server when asked.
                (X509Certificate[] arg0, String arg1) -> true) // Here, we override the callback to never check the server's certificate.
                .build();
        httpClient = HttpClients.custom().setSSLContext(clientSSLContext).build();

        String baseUrl = getBaseUrl(server);
        HttpGet httpGet = new HttpGet("https://" + baseUrl + "/echo/this");
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpGet);
        }
        finally {
            if (httpResponse != null) {
                System.out.println(Str.and("httpsRequest_embeddedServer_1WaySSL_SSLWithoutAnyValidation_Returns200OK - Response.Status:\t", httpResponse.getStatusLine()));
                System.out.println(Str.and("httpsRequest_embeddedServer_1WaySSL_SSLWithoutAnyValidation_Returns200OK - Response:\t", httpResponse.toString(), "/n"));

                httpResponse.close();
            }

            httpClient.close();
            server.stop();
        }
    }

    /**
     Scenario: Client does not validate any certificate in its SSLContext. It allows an SSL connection with any server.
     This time, we tell the client to trust all certificates presented to it, so certificate
     validation is bypassed and the request succeeds.
     */
    public void httpsRequest_externalServer_1WaySSL_ValidatingCertsButNoClientTrustStore_ThrowsSSLException(String SERVER_KEYSTORE, char[] KEYPASS_AND_STOREPASS_VALUE)
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException
    {
        SSLContext clientSSLContext = new SSLContextBuilder().loadTrustMaterial(
                NO_CLIENT_KEYSTORE, // Client does not have a store from which to present its certificate to the server when asked.
                (X509Certificate[] arg0, String arg1) -> true) // Here, we override the callback to never check the server's certificate.
                .build();
        httpClient = HttpClients.custom().setSSLContext(clientSSLContext).build();

        HttpGet httpGet = new HttpGet("https://localhost:443");
        CloseableHttpResponse httpResponse = null;

        try {
            httpResponse = httpClient.execute(httpGet);
        }
        catch(Exception ex) {
            System.out.println(Str.and("httpsRequest_externalServer_1WaySSL_ValidatingCertsButNoClientTrustStore_ThrowsSSLException - Full Exception: ", ex.toString()));
            System.out.println(Str.and("httpsRequest_externalServer_1WaySSL_ValidatingCertsButNoClientTrustStore_ThrowsSSLException - Cause: ", ex.getCause()));
        }
        finally {
            httpResponse.close();
            httpClient.close();
        }

        System.out.println(Str.and("httpsRequest_externalServer_1WaySSL_ValidatingCertsButNoClientTrustStore_ThrowsSSLException - Response.Status:\t", httpResponse.getStatusLine()));
        System.out.println(Str.and("httpsRequest_externalServer_1WaySSL_ValidatingCertsButNoClientTrustStore_ThrowsSSLException - Response:\t", httpResponse.toString()));
    }

    /**
     Scenario: Client does not validate any certificate in its SSLContext. It allows an SSL connection with any server.
     This time, we tell the client to trust all certificates presented to it, so certificate
     validation is bypassed and the request succeeds.
     */
    public void httpsRequest_With1WaySSLAndTrustingAllCertsButNoClientTrustStore_Returns200OK(String SERVER_KEYSTORE, char[] KEYPASS_AND_STOREPASS_VALUE)
            throws Exception
    {
        SSLContext clientSSLContext = new SSLContextBuilder().loadTrustMaterial(
                NO_CLIENT_KEYSTORE,
                (X509Certificate[] arg0, String arg1) -> true) // Basically, don't event check the server certificate.
                .build();
        httpClient = HttpClients.custom().setSSLContext(clientSSLContext).build();

        SSLContext serverSSLContext = createServerSSLContext(SERVER_KEYSTORE, NO_SERVER_TRUST_MANAGER, KEYPASS_AND_STOREPASS_VALUE);
        final HttpServer server = createLocalTestServer(serverSSLContext, ONE_WAY_SSL); //
        server.start();

        String baseUrl = getBaseUrl(server);
        HttpGet httpGet = new HttpGet("https://" + baseUrl + "/echo/this");
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpGet);

        } finally {
            httpResponse.close();
            httpClient.close();
            server.stop();
        }

        System.out.println(Str.and("httpsRequest_With1WaySSLAndTrustingAllCertsButNoClientTrustStore_Returns200OK - Response.Status:\t", httpResponse.getStatusLine()));
        System.out.println(Str.and("httpsRequest_With1WaySSLAndTrustingAllCertsButNoClientTrustStore_Returns200OK - Response:\t", httpResponse.toString()));
    }

    /**
     Scenario: Client validates the Server's identity.
     Unlike the previous test, the HTTP Client's SSLContext is configured with the client's TrustStore, which contains the Server's certificate. This allows it to verify the Server's identity.
     */
    public void httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK(String SERVER_KEYSTORE, String CLIENT_TRUSTSTORE, char[] KEYPASS_AND_STOREPASS_VALUE)
            throws Exception
    {
        SSLContext serverSSLContext = createServerSSLContext(SERVER_KEYSTORE, NO_SERVER_TRUST_MANAGER, KEYPASS_AND_STOREPASS_VALUE);
        final HttpServer server = createLocalTestServer(serverSSLContext, ONE_WAY_SSL);
        server.start();

        // The server certificate was imported into the client's TrustStore (using keytool -import)
        KeyStore clientTrustStore = getStore(CLIENT_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);

        SSLContext clientSSLContext = new SSLContextBuilder()
                .loadTrustMaterial(
                        clientTrustStore,
                        new TrustSelfSignedStrategy())
                .build();
        httpClient = HttpClients.custom().setSSLContext(clientSSLContext).build();

        String baseUrl = getBaseUrl(server);
        HttpGet httpGet = new HttpGet("https://" + baseUrl + "/echo/this");
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpGet);

        } finally {
            httpResponse.close();
            httpClient.close();
            server.stop();
        }

        System.out.println(Str.and("httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK - Response.Status:\t", httpResponse.getStatusLine()));
        System.out.println(Str.and("httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK - Response:\t", httpResponse.toString()));
    }

    // 2-WAY SSL TESTS
    /**
     Scenario:
     Set up a LocalTestServer that requires client certificates. The server's TrustStore does
     not contain the CA certificate because it's not instantiated (it's NO_SERVER_TRUST_MANAGER = null). This means that there's no way to verify that the signature on the client certificate is from a
     trust CA. The SSL handshake will fail.
     */
    // TODO: Update method signature, since the null here seems to be the SERVER_TRUSTSTORE
    public void httpsRequest_With2WaySSLAndUnknownClientCert_ThrowsSSLExceptionBadCertificate(String SERVER_KEYSTORE, String CLIENT_KEYSTORE, String SERVER_TRUSTSTORE, String CLIENT_TRUSTSTORE, char[] KEYPASS_AND_STOREPASS_VALUE)
            throws Exception
    {
        SSLContext serverSSLContext = createServerSSLContext(SERVER_KEYSTORE, NO_SERVER_TRUST_MANAGER, KEYPASS_AND_STOREPASS_VALUE);
        final HttpServer server = createLocalTestServer(serverSSLContext, TWO_WAY_SSL);
        server.start();
        String baseUrl = getBaseUrl(server);
        HttpGet httpGet = new HttpGet("https://" + baseUrl + "/echo/this");
        HttpResponse httpResponse = null;

        KeyStore clientTrustStore = getStore(CLIENT_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);
        KeyStore clientKeyStore = getStore(CLIENT_KEYSTORE, KEYPASS_AND_STOREPASS_VALUE);
        SSLContext sslContext = new SSLContextBuilder()
                .loadTrustMaterial(clientTrustStore, new TrustSelfSignedStrategy())
                .loadKeyMaterial(clientKeyStore, KEYPASS_AND_STOREPASS_VALUE)
                .build();
        httpClient = HttpClients.custom().setSSLContext(sslContext).build();

        try {
            httpClient.execute(httpGet);
        } finally {
            server.stop();
        }

        System.out.println(Str.and("httpsRequest_With2WaySSLAndUnknownClientCert_ThrowsSSLExceptionBadCertificate - Response.Status:\t", httpResponse.getStatusLine()));
        System.out.println(Str.and("httpsRequest_With2WaySSLAndUnknownClientCert_ThrowsSSLExceptionBadCertificate - Response:\t", httpResponse.toString()));
    }

    /**
     The client is not configured with a KeyStore, meaning it will not present a client
     certificate to the server resulting in a failed SSL handshake
     */
    public void httpsRequest_With2WaySSLButNoClientKeyStore_ThrowsSSLExceptionBadCertificate(String SERVER_KEYSTORE, String CLIENT_KEYSTORE, String SERVER_TRUSTSTORE, String CLIENT_TRUSTSTORE, char[] KEYPASS_AND_STOREPASS_VALUE)
            throws Exception
    {
        // load the server's truststore file into a KeyStore and create a TrustManager array from it
        KeyStore serverTrustStore = getStore(SERVER_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);
        TrustManager[] serverTrustManagers = getTrustManagers(serverTrustStore);
        SSLContext serverSSLContext = createServerSSLContext(SERVER_KEYSTORE,
                serverTrustManagers, KEYPASS_AND_STOREPASS_VALUE);
        final HttpServer server = createLocalTestServer(serverSSLContext, TWO_WAY_SSL);
        server.start();

        // MISSING clientKeyStore
        KeyStore clientTrustStore = getStore(CLIENT_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);
        SSLContext sslContext = new SSLContextBuilder()
                // no client KeyStore added to the SSLContext configuration, therefore no client certificate will be presented for the SSL Handshake.
                .loadTrustMaterial(clientTrustStore, new TrustSelfSignedStrategy())
                .build();
        httpClient = HttpClients.custom().setSSLContext(sslContext).build();

        String baseUrl = getBaseUrl(server);
        HttpGet httpGet = new HttpGet("https://" + baseUrl + "/echo/this");
        HttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpGet);
        } finally {
            server.stop();
        }

        System.out.println(Str.and("httpsRequest_With2WaySSLButNoClientKeyStore_ThrowsSSLExceptionBadCertificate - Response.Status:\t", httpResponse.getStatusLine()));
        System.out.println(Str.and("httpsRequest_With2WaySSLButNoClientKeyStore_ThrowsSSLExceptionBadCertificate - Response:\t", httpResponse.toString()));
    }


    public void httpsRequest_With2WaySSLAndHasValidKeyStoreAndTrustStore_Returns200OK(String SERVER_KEYSTORE, String CLIENT_KEYSTORE, String SERVER_TRUSTSTORE, String CLIENT_TRUSTSTORE, char[] KEYPASS_AND_STOREPASS_VALUE)
            throws Exception {

        KeyStore serverTrustStore = getStore(SERVER_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);
        TrustManager[] serverTrustManagers = getTrustManagers(serverTrustStore);
        SSLContext serverSSLContext = createServerSSLContext(SERVER_KEYSTORE, serverTrustManagers, KEYPASS_AND_STOREPASS_VALUE);
        final HttpServer server = createLocalTestServer(serverSSLContext, TWO_WAY_SSL);
        server.start();

        KeyStore clientTrustStore = getStore(CLIENT_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);
        KeyStore clientKeyStore = getStore(CLIENT_KEYSTORE, KEYPASS_AND_STOREPASS_VALUE);
        SSLContext sslContext = new SSLContextBuilder()
                .loadTrustMaterial(clientTrustStore, new TrustSelfSignedStrategy())
                .loadKeyMaterial(clientKeyStore, KEYPASS_AND_STOREPASS_VALUE)
                .build();
        httpClient = HttpClients.custom().setSSLContext(sslContext).build();

        String baseUrl = getBaseUrl(server);
        HttpGet httpGet = new HttpGet("https://" + baseUrl + "/echo/this");
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpGet);
        } finally {
            httpResponse.close();
            server.stop();
        }

        System.out.println(Str.and("httpsRequest_With2WaySSLAndHasValidKeyStoreAndTrustStore_Returns200OK - Response.Status:\t", httpResponse.getStatusLine()));
        System.out.println(Str.and("httpsRequest_With2WaySSLAndHasValidKeyStoreAndTrustStore_Returns200OK - Response:\t", httpResponse.toString()));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Note: forceSSLAuth forces client certificate authentication
    protected HttpServer createLocalTestServer(SSLContext sslContext, boolean forceSSLAuth)
            throws UnknownHostException
    {
        final HttpServer server = ServerBootstrap.bootstrap()
                .setLocalAddress(Inet4Address.getByName("localhost"))
                .setSslContext(sslContext)
                .setSslSetupHandler(socket -> socket.setNeedClientAuth(forceSSLAuth))
                .registerHandler("*",
                        (request, response, context) -> response.setStatusCode(HttpStatus.SC_OK))
                .create();

        return server;
    }

    /**
     Create an SSLContext for the server using the server's JKS. This instructs the server to
     present its certificate when clients connect over HTTPS.
     */
    protected SSLContext createServerSSLContext(final String keyStoreFileName, TrustManager[] serverTrustManagers, final char[] password)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, KeyManagementException
    {
        KeyStore serverKeyStore = getStore(keyStoreFileName, password);
        KeyManager[] serverKeyManagers = getKeyManagers(serverKeyStore, password);

        SSLContext sslContext = SSLContexts.custom().useProtocol(PROTOCOL).build();
        sslContext.init(serverKeyManagers, serverTrustManagers, new SecureRandom());

        return sslContext;
    }

    /**
     * KeyStores provide credentials, TrustStores verify credentials.
     *
     * Server KeyStores stores the server's private keys, and certificates for corresponding public
     * keys. Used here for HTTPS connections over localhost.
     *
     * Client TrustStores store servers' certificates.
     */
    protected KeyStore getStore(final String storeFileFullpath, final char[] password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException
    {
        final KeyStore store = KeyStore.getInstance(JAVA_KEYSTORE);
        final InputStream clientStoreFile = new FileInputStream(storeFileFullpath);
        try
        {
            store.load(clientStoreFile, password);
        }
        finally
        {
            clientStoreFile.close();
        }

        return store;
    }

    /**
     * KeyManagers decide which authentication credentials (e.g. certs) should be sent to the remote
     * host for authentication during the SSL handshake.
     *
     * Server KeyManagers use their private keys during the key exchange algorithm and send
     * certificates corresponding to their public keys to the clients. The certificate comes from
     * the KeyStore.
     */
    protected KeyManager[] getKeyManagers(KeyStore store, final char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException
    {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(store, password);

        return keyManagerFactory.getKeyManagers();
    }


    /**
     * TrustManagers determine if the remote connection should be trusted or not.
     *
     * Clients will use certificates stored in their TrustStores to verify identities of servers.
     * Servers will use certificates stored in their TrustStores to verify identities of clients.
     */
    protected TrustManager[] getTrustManagers(KeyStore store)
            throws NoSuchAlgorithmException, KeyStoreException
    {
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(store);

        return trustManagerFactory.getTrustManagers();
    }


    protected String getBaseUrl(HttpServer server) {
        return server.getInetAddress().getHostName() + ":" + server.getLocalPort();
    }

}
