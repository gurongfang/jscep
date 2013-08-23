package org.jscep.server;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.client.EnrollmentResponse;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.EnrollmentTransaction;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transport.*;
import org.jscep.transport.TransportFactory.Method;
import org.jscep.transport.request.GetCaCapsRequest;
import org.jscep.transport.request.GetCaCertRequest;
import org.jscep.transport.request.GetNextCaCertRequest;
import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.GetCaCapsResponseHandler;
import org.jscep.transport.response.GetCaCertResponseHandler;
import org.jscep.transport.response.GetNextCaCertResponseHandler;
import org.jscep.util.X500Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ScepServletTest {
    private static String PATH = "/scep/pkiclient.exe";
    private BigInteger goodSerial;
    private BigInteger badSerial;
    private X500Name name;
    private X500Name pollName;
    private PrivateKey priKey;
    private PublicKey pubKey;
    private X509Certificate sender;
    private Server server;
    private int port;
    private String goodIdentifier;
    private String badIdentifier;
    private TransportFactory transportFactory;

    @Before
    public void configureFixtures() throws Exception {
        name = new X500Name("CN=rguioscert.labs.microstrategy.com");
        pollName = new X500Name("CN=Poll");
        goodSerial = BigInteger.ONE;
        badSerial = BigInteger.ZERO;
        goodIdentifier = null;
        badIdentifier = "bad";
        KeyPair keyPair = readPublicAndPrivateKey();
        //KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        priKey = keyPair.getPrivate();
        pubKey = keyPair.getPublic();
        sender = readCertificate();
        //sender = generateCertificate();
        transportFactory = new UrlConnectionTransportFactory();

    }
    private X509Certificate generateCertificate() throws Exception {
        ContentSigner signer;
        try {
            signer = new JcaContentSignerBuilder("SHA1withRSA").build(priKey);
        } catch (OperatorCreationException e) {
            throw new Exception(e);
        }
        Calendar cal = GregorianCalendar.getInstance();
        cal.add(Calendar.YEAR, -1);
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, 2);
        Date notAfter = cal.getTime();
        JcaX509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(
                name, BigInteger.ONE, notBefore, notAfter, name, pubKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    @Before
    public void startUp() throws Exception {
        final ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(ScepServletImpl.class, PATH);

        server = new Server(0);
        server.setHandler(handler);
        server.start();

        port = server.getConnectors()[0].getLocalPort();
    }

    @After
    public void shutDown() throws Exception {
        server.stop();
    }

    private URL getURL() throws MalformedURLException {
        return new URL("http", "localhost", port, PATH);
    }

    private X509Certificate getRecipient() throws Exception {
        GetCaCertRequest req = new GetCaCertRequest();
        Transport transport = getTransport(getURL());

        CertStore store = transport.sendRequest(req,
                new GetCaCertResponseHandler());
        Collection<? extends Certificate> certs = store.getCertificates(null);

        if (certs.size() > 0) {
            return (X509Certificate) certs.iterator().next();
        } else {
            return null;
        }
    }

    @Test
    public void testGetCaCaps() throws Exception {
        GetCaCapsRequest req = new GetCaCapsRequest();
        Transport transport = getTransport(getURL());
        Capabilities caps = transport.sendRequest(req,
                new GetCaCapsResponseHandler());

        System.out.println(caps);
    }

    @Test
    public void getNextCaCertificateGood() throws Exception {
        GetNextCaCertRequest req = new GetNextCaCertRequest(goodIdentifier);
        Transport transport = getTransport(getURL());
        CertStore certs = transport.sendRequest(req,
                new GetNextCaCertResponseHandler(getRecipient()));

        assertThat(certs.getCertificates(null).size(), is(1));
    }

    @Test(expected = TransportException.class)
    public void getNextCaCertificateBad() throws Exception {
        GetNextCaCertRequest req = new GetNextCaCertRequest(badIdentifier);
        Transport transport = getTransport(getURL());
        CertStore certs = transport.sendRequest(req,
                new GetNextCaCertResponseHandler(getRecipient()));

        assertThat(certs.getCertificates(null).size(), is(1));
    }

    @Test
    public void testGetCRL() throws Exception {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, goodSerial);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DESede");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        Transaction t = new NonEnrollmentTransaction(transport, encoder,
                decoder, iasn, MessageType.GET_CRL);
        State s = t.send();

        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testGetCertBad() throws Exception {
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, badSerial);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        Transaction t = new NonEnrollmentTransaction(transport, encoder,
                decoder, iasn, MessageType.GET_CERT);
        State s = t.send();

        assertThat(s, is(State.CERT_NON_EXISTANT));
    }
    private EncodedKeySpec generateSpec(String filename,boolean isPublic) throws Exception
    {

    	File f = new File(filename);
    	FileInputStream fis = new FileInputStream(f);
    	DataInputStream dis = new DataInputStream(fis);
    	byte[] keyBytes = new byte[(int)f.length()];
    	dis.readFully(keyBytes);
    	dis.close();
    	if(isPublic)
    		return new X509EncodedKeySpec(keyBytes);
    	else
    		return new PKCS8EncodedKeySpec(keyBytes);
    }

    private X509Certificate readCertificate() throws Exception {
    	 FileInputStream fis = null;
    	 ByteArrayInputStream bais = null;
    	  // use FileInputStream to read the file
    	  fis = new FileInputStream("src/test/resources/CRootCA.der");
    	  
    	  // read the bytes
    	  byte value[] = new byte[fis.available()];
    	  fis.read(value);
    	  fis.close();
    	  bais = new ByteArrayInputStream(value);
    	  
    	  // get X509 certificate factory
    	  CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    	   
    	  // certificate factory can now create the certificate 
    	  return (X509Certificate)certFactory.generateCertificate(bais);
    }
    private KeyPair readPublicAndPrivateKey() throws Exception
    {
    	KeyFactory kf = KeyFactory.getInstance("RSA");
    	PrivateKey privateKey =  kf.generatePrivate(generateSpec("src/test/resources/private_key.der",false));
    	PublicKey publicKey =  kf.generatePublic(generateSpec("src/test/resources/public_key.der",true));
    	KeyPair keyPair = new KeyPair(publicKey,privateKey);
    	return keyPair;
    }
    public static X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, PublicKey caPublic)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException,
            OperatorCreationException, CertificateException {   

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                .find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                .find(sigAlgId);

        AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate
                .getEncoded());
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(caPublic.getEncoded());

        PKCS10CertificationRequest pk10Holder = inputCSR;
        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                new X500Name("CN=rguioscert.labs.microstrategy.com"), new BigInteger("1"), new Date(
                        System.currentTimeMillis()), new Date(
                        System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60
                                * 1000), pk10Holder.getSubject(), keyInfo);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                .build(foo);        

        X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
        org.bouncycastle.asn1.x509.Certificate eeX509CertificateStructure = holder
                .toASN1Structure(); 

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Read Certificate
        InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
        X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
        is1.close();
        return theCert;
        //return null;
    }
    private void writeCertificate(Certificate cert,String filename) throws Exception
    {
    	final FileOutputStream os = new FileOutputStream(filename);  
    	os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));  
    	os.write(Base64.encodeBase64(cert.getEncoded(), true));  
    	os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));  
    	os.close(); 
    }
    @Test
    public void testEnroll2() throws Exception {
    	FileReader fileReader = new FileReader("src/test/resources/client.csr");
    	PemReader pemReader = new PemReader(fileReader);
    	PKCS10CertificationRequest csr = new PKCS10CertificationRequest(pemReader.readPemObject().getContent());
    	fileReader.close();
    	pemReader.close();
    	

    	    
    	PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
    			getRecipient(), "DESede");
    	PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
    			envEncoder);
    	System.out.println("============================================================================================================");
    	System.out.println(getRecipient());
    	System.out.println("============================================================================================================");
    	PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
    			priKey);
    	PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
    			envDecoder);

    	Transport transport = getTransport(getURL());
    	Transaction t = new EnrollmentTransaction(transport, encoder, decoder,
    			csr);

    	State s = t.send();
    	assertThat(s, is(State.CERT_ISSUED));
    	Collection<? extends Certificate> cs= t.getCertStore().getCertificates(null);
    	Certificate cert = cs.iterator().next();
    	writeCertificate(cert,"src/test/resources/clientFromCA(jscep).der");
    	writeCertificate(sign(csr,priKey,pubKey),"src/test/resources/clientFromCA2.der");
    }
    
    @Test
    public void testEnrollmentGet() throws Exception {
        PKCS10CertificationRequest csr = getCsr(name, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DESede");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        Transaction t = new EnrollmentTransaction(transport, encoder, decoder,
                csr);

        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testEnrollmentPost() throws Exception {
        PKCS10CertificationRequest csr = getCsr(name, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        Transaction t = new EnrollmentTransaction(transport, encoder, decoder,
                csr);

        State s = t.send();
        assertThat(s, is(State.CERT_ISSUED));
    }

    @Test
    public void testEnrollmentWithPoll() throws Exception {
        PKCS10CertificationRequest csr = getCsr(pollName, pubKey, priKey,
                "password".toCharArray());

        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipient(), "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, sender,
                envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(sender,
                priKey);
        PkiMessageDecoder decoder = new PkiMessageDecoder(getRecipient(),
                envDecoder);

        Transport transport = getTransport(getURL());
        EnrollmentTransaction trans = new EnrollmentTransaction(transport,
                encoder, decoder, csr);
        State state = trans.send();
        assertThat(state, is(State.CERT_REQ_PENDING));

        IssuerAndSubject ias = new IssuerAndSubject(X500Utils.toX500Name(sender
                .getIssuerX500Principal()), pollName);
        trans = new EnrollmentTransaction(transport, encoder, decoder, ias,
                trans.getId());
        state = trans.send();
        assertThat(state, is(State.CERT_REQ_PENDING));
    }

    private PKCS10CertificationRequest getCsr(X500Name subject,
            PublicKey pubKey, PrivateKey priKey, char[] password)
            throws GeneralSecurityException, IOException {
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey
                .getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
                "SHA1withRSA");
        ContentSigner signer;
        try {
            signer = signerBuilder.build(priKey);
        } catch (OperatorCreationException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
                subject, pkInfo);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                new DERPrintableString(new String(password)));

        return builder.build(signer);
    }

    private Transport getTransport(URL url) {
        return transportFactory.forMethod(Method.GET, url);
    }
}
