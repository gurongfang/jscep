package org.jscep.example;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
//import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.jscep.CertificateVerificationCallback;
import org.jscep.client.Client;
//import org.jscep.transaction.EnrolmentTransaction;
import org.jscep.transaction.Transaction;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import org.jscep.server.ScepServletTest;
public class SimpleExample {
	public static void main(String[] args) throws Exception {
		final KeyStore store = KeyStore.getInstance("JKS");
		store.load(new FileInputStream("src/test/resources/ServerKeyStore.jks"), "tomcat".toCharArray());

		final URL url = new URL("http://pilotonsiteipsec.verisign.com/cgi-bin/pkiclient.exe");
		final X509Certificate identity = (X509Certificate) store.getCertificate("CRootCA");
		final PrivateKey privKey = (PrivateKey) store.getKey("tomcat", "tomcat".toCharArray());
		System.out.println(identity.toString());
		for (Enumeration<String> e =store.aliases(); e.hasMoreElements();)
		{
			String each = e.nextElement();
		    System.out.println( each+" "+store.isKeyEntry(each));
		}
		System.out.println(privKey.toString());
		ScepServletTest test= new ScepServletTest();
		test.startUp();
		test.testEnroll2();
//		final CallbackHandler cbh = new ConsoleCallbackHandler();
//
//		String signatureAlgorithm = "SHA1withRSA";
//		X500Principal subject = new X500Principal("CN=example.jscep.org");
//		DERObjectIdentifier attrType = PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
//		ASN1Set attrValues = new DERSet(new DERPrintableString("95835B16B498"));
//		DEREncodable password = new Attribute(attrType, attrValues);
//		ASN1Set attributes = new DERSet(password);
//
//		Security.addProvider(new BouncyCastleProvider());
//		PKCS10CertificationRequest csr = new PKCS10CertificationRequest(signatureAlgorithm, subject, identity.getPublicKey(), attributes, privKey);
//
//		final Client scepClient = new Client(url, identity, privKey, cbh, "jscep.org");
//		EnrolmentTransaction trans = scepClient.enrol(csr);
//		Transaction.State state = trans.send();
//		if (state == Transaction.State.CERT_NON_EXISTANT) {
//			System.out.println(trans.getFailInfo());
//		}
	}
        
//        private static class ConsoleCallbackHandler implements CallbackHandler {
//                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
//                        for (int i = 0; i < callbacks.length; i++) {
//                if (callbacks[i] instanceof CertificateVerificationCallback) {
//                    CertificateVerificationCallback callback = (CertificateVerificationCallback) callbacks[i];
//                    callback.setVerified(true);
//                } else {
//                                        throw new UnsupportedCallbackException(callbacks[i]);
//                                }
//                        }
//                }
//                
//        }
}