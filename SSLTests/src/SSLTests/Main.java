package SSLTests;

import com.sinequa.common.Str;
import com.sinequa.common.Sys;

public class Main
{
    private static final char[] KEYPASS_AND_STOREPASS_VALUE = "mysecret".toCharArray();
    private static final String SSLRoot = "C:\\4.Sinequa\\TwoWaySSL\\Apache24\\ssl";
    private static final String SERVER_KEYSTORE = Str.and(SSLRoot, "\\server_keystore.jks");
    private static final String SERVER_TRUSTSTORE = Str.and(SSLRoot, "\\server_truststore.jks");
    private static final String CLIENT_KEYSTORE = Str.and(SSLRoot, "\\client_keystore.jks");
    private static final String CLIENT_TRUSTSTORE = Str.and(SSLRoot, "\\client_truststore.jks");

    public static void main(String[] args)
        throws Exception
    {
//	    System.out.println(Str.and("test"));
        SSLTests TestModule = new SSLTests();

        try {
            TestModule.httpRequest_embeddedServer_Returns200OK();
        } catch(Exception e) {
            Sys.logError(Str.and("httpRequest_embeddedServer_Returns200OK - ", e.toString()));
        }

        try {
            TestModule.httpRequest_externalServer_Returns200OK();
        } catch (Exception e) {
            Sys.logError(Str.and("httpRequest_externalServer_Returns200OK - ", e.toString()));
        }

        try { TestModule.httpsRequest_With1WaySSLAndTrustingAllCertsButNoClientTrustStore_Returns200OK(SERVER_KEYSTORE, KEYPASS_AND_STOREPASS_VALUE);
        } catch (Exception e) {
            Sys.logError(Str.and("httpsRequest_With1WaySSLAndTrustingAllCertsButNoClientTrustStore_Returns200OK - ", e.toString()));
        }

        try {
            TestModule.httpsRequest_embeddedServer_1WaySSL_SSLWithoutAnyValidation_Returns200OK(SERVER_KEYSTORE, KEYPASS_AND_STOREPASS_VALUE);
        } catch (Exception e) {
            Sys.logError(Str.and("httpsRequest_ExternalServer_WithoutClientCertificate_SSLHandshakeError {OUTER EXCEPTION} - ", e.toString()));
        }

//        //PASSES: The embedded server is spun up without any SSL context and with instructions to always set the status code to 200.
//        tests.httpRequest_embeddedServer_Returns200OK();
//
//        // PASSES: There is a virtual host configured to handle clear HTTP connections on our external Apache server.
//        tests.httpRequest_externalServer_Returns200OK();
//
//        // PASSES: Client and server have an SSL Context for HTTPS, but the server does not validate the client and the client accepts any server.
//        tests.httpsRequest_embeddedServer_1WaySSL_SSLWithoutAnyValidation_Returns200OK(SERVER_KEYSTORE, KEYPASS_AND_STOREPASS_VALUE);
//
//        // FAILS (Throws SSLHandshakeException): Server's certificate does not exist in the client's TrustStore. This means that the client cannot validate the server's identity, which kills the SSL handshake.
//        tests.httpsRequest_externalServer_1WaySSL_ValidatingCertsButNoClientTrustStore_ThrowsSSLException(SERVER_KEYSTORE, KEYPASS_AND_STOREPASS_VALUE);
//
//        // PASSES: Validation is bypassed by always returning true when loading the Client's TrustStore materials.
//        //tests.httpsRequest_With1WaySSLAndTrustingAllCertsButNoClientTrustStore_Returns200OK(SERVER_KEYSTORE, KEYPASS_AND_STOREPASS_VALUE);
//
//        // PASSES: Server sends its certificate to the Client. Client verifies Server's identity by checking for the presence of the Server's cert in its TrustStore. Server DOESNT verify Client's certificate.
//        //tests.httpsRequest_With1WaySSLAndValidatingCertsAndClientTrustStore_Returns200OK(SERVER_KEYSTORE, CLIENT_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);
//
//        // FAILS(Throws SSLHandshakeException): Server has no way to validate the signature of the Client certificate because no SERVER_TRUSTSTORE is instantiated.
//        //test.httpsRequest_With2WaySSLAndUnknownClientCert_ThrowsSSLExceptionBadCertificate(SERVER_KEYSTORE, CLIENT_TRUSTSTORE, CLIENT_KEYSTORE, KEYPASS_AND_STOREPASS_VALUE);
//
//        // FAILS (Throws SSLHandshakeException): Server
//        //test.httpsRequest_With2WaySSLButNoClientKeyStore_ThrowsSSLExceptionBadCertificate(SERVER_KEYSTORE, CLIENT_KEYSTORE, SERVER_TRUSTSTORE, CLIENT_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);
//
//        // PASSES:
//        //tests.httpsRequest_With2WaySSLAndHasValidKeyStoreAndTrustStore_Returns200OK(SERVER_KEYSTORE, CLIENT_KEYSTORE, SERVER_TRUSTSTORE, CLIENT_TRUSTSTORE, KEYPASS_AND_STOREPASS_VALUE);

    }
}
