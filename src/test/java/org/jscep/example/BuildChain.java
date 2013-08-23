package org.jscep.example;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

public class BuildChain {
  public static KeyPair generateRSAKeyPair() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
    kpGen.initialize(1024, new SecureRandom());
    return kpGen.generateKeyPair();
  }

  @SuppressWarnings("deprecation")
public static PKCS10CertificationRequest generateRequest(KeyPair pair) throws Exception {
    return new PKCS10CertificationRequest("SHA256withRSA", new X500Principal(
        "CN=Requested Test Certificate"), pair.getPublic(), null, pair.getPrivate());
  }

  @SuppressWarnings("deprecation")
public static X509Certificate generateV1Certificate(KeyPair pair) throws InvalidKeyException,
      NoSuchProviderException, SignatureException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();

    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
    certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
    certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
    certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
    certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
    certGen.setPublicKey(pair.getPublic());
    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

    return certGen.generateX509Certificate(pair.getPrivate(), "BC");
  }
  private static EncodedKeySpec generateSpec(String filename,boolean isPublic) throws Exception
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
  private static KeyPair readPublicAndPrivateKey() throws Exception
  {
  	KeyFactory kf = KeyFactory.getInstance("RSA");
  	PrivateKey privateKey =  kf.generatePrivate(generateSpec("src/test/resources/private_key.der",false));
  	PublicKey publicKey =  kf.generatePublic(generateSpec("src/test/resources/public_key.der",true));
  	KeyPair keyPair = new KeyPair(publicKey,privateKey);
  	return keyPair;
  }
  private static X509Certificate readCertificate() throws Exception {
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
private static PKCS10CertificationRequest readCSR() throws Exception{
	FileReader fileReader = new FileReader("src/test/resources/client.csr");
	PemReader pemReader = new PemReader(fileReader);
	PKCS10CertificationRequest csr = new PKCS10CertificationRequest(pemReader.readPemObject().getContent());
	fileReader.close();
	pemReader.close();
	return csr;
}
  @SuppressWarnings("deprecation")
public static X509Certificate[] buildChain() throws Exception {
    KeyPair pair = generateRSAKeyPair();
    PKCS10CertificationRequest request = generateRequest(pair);
    request = readCSR();
    
    KeyPair rootPair = generateRSAKeyPair();
    rootPair = readPublicAndPrivateKey();
    X509Certificate rootCert = generateV1Certificate(rootPair);
    rootCert = readCertificate();

    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
    certGen.setIssuerDN(rootCert.getSubjectX500Principal());
    certGen.setNotBefore(new Date(System.currentTimeMillis()));
    certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
    X500Principal              dnName = new X500Principal("CN=10.197.41.74");
    certGen.setSubjectDN(dnName);
    //certGen.setSubjectDN(request.getCertificationRequestInfo().getSubject());
    certGen.setPublicKey(request.getPublicKey("BC"));
    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

    certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
        new AuthorityKeyIdentifierStructure(rootCert));

    certGen.addExtension(X509Extensions.SubjectKeyIdentifier,

    false, new SubjectKeyIdentifierStructure(request.getPublicKey("BC")));

    certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

    certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
        | KeyUsage.keyEncipherment));

    certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
        KeyPurposeId.id_kp_serverAuth));

    ASN1Set attributes = request.getCertificationRequestInfo().getAttributes();

    if(attributes!=null)
    {
        for (int i = 0; i != attributes.size(); i++) {
            Attribute attr = Attribute.getInstance(attributes.getObjectAt(i));

            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
              X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0));

              Enumeration e = extensions.oids();
              while (e.hasMoreElements()) {
                DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                X509Extension ext = extensions.getExtension(oid);

                certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
              }
            }
          }
    }
    X509Certificate issuedCert = certGen.generateX509Certificate(rootPair.getPrivate());

    return new X509Certificate[] { issuedCert, rootCert };
  }

  public static void main(String[] args) throws Exception {
	  String filename = "src/test/resources/clientFromCA3.der";
  	final FileOutputStream os = new FileOutputStream(filename);  
  	
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    X509Certificate[] chain = buildChain();

    //PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
    PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(os));

    pemWrt.writeObject(chain[0]);
    pemWrt.writeObject(chain[1]);

    pemWrt.close();  
  	os.close(); 
  }
}