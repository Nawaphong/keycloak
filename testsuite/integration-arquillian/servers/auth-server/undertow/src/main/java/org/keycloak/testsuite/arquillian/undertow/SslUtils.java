package org.keycloak.testsuite.arquillian.undertow;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jboss.resteasy.util.ReadFromStream;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.common.util.PemUtils;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.saml.common.util.StringUtil;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

public class SslUtils {

    static {
        BouncyIntegration.init();
    }
    // "/home/bburke/openshift-local-clusterup/openshift-apiserver/master.server.crt"
    // "/home/bburke/openshift-local-clusterup/openshift-apiserver/master.server.key"

    public static SSLContext fromPems(String privateKeyFile, String certificateFile) throws Exception {
        FileInputStream fis = new FileInputStream(certificateFile);
        String crt = StreamUtil.readString(fis);
        fis.close();
        fis = new FileInputStream(privateKeyFile);
        String key = StreamUtil.readString(fis);
        fis.close();
        X509Certificate x509 = PemUtils.decodeCertificate(crt);
        PrivateKey privateKey = PemUtils.decodePrivateKey(key);

        SSLContext sslContext = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        X509Certificate[] chain = {x509};
        keyStore.setKeyEntry("main", privateKey, "654321".toCharArray(), chain);
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, "654321".toCharArray());
        TrustManager[] tm = {new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        sslContext = SSLContext.getInstance("tls");
        sslContext.init(keyManagerFactory.getKeyManagers(), tm, null);


        return sslContext;
    }

    /**
     * Generates a localhost SSLContext that is usable in browsers.  Loops through all available ip4 addresses
     * and adds them to subject alternatives
     *
     * @return
     * @throws Exception
     */
    public static SSLContext generateLocalhostContext() throws Exception {
        String subjectName = "localhost";
        SecureRandom random = new SecureRandom();

// create keypair
        KeyPairGenerator keypairGen = KeyPairGenerator.getInstance("RSA");
        keypairGen.initialize(2048, random);
        KeyPair keypair = keypairGen.generateKeyPair();

// fill in certificate fields
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, subjectName)
                .build();
        byte[] id = new byte[20];
        random.nextBytes(id);
        BigInteger serial = new BigInteger(160, random);

        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter = new Date(System.currentTimeMillis() + (((1000L * 60 * 60 * 24 * 30)) * 12) * 3);

        X509v3CertificateBuilder certificate = new JcaX509v3CertificateBuilder(
                subject,
                serial,
                notBefore,
                notAfter,
                subject,
                keypair.getPublic());
        certificate.addExtension(Extension.subjectKeyIdentifier, false, id);
        certificate.addExtension(Extension.authorityKeyIdentifier, false, id);
        BasicConstraints constraints = new BasicConstraints(true);
        certificate.addExtension(
                Extension.basicConstraints,
                true,
                constraints.getEncoded());
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
        certificate.addExtension(Extension.keyUsage, false, usage.getEncoded());
        ExtendedKeyUsage usageEx = new ExtendedKeyUsage(new KeyPurposeId[]{
                KeyPurposeId.id_kp_serverAuth,
                KeyPurposeId.id_kp_clientAuth
        });
        certificate.addExtension(
                Extension.extendedKeyUsage,
                false,
                usageEx.getEncoded());
        GeneralNamesBuilder alternatives = new GeneralNamesBuilder();

        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface nic = networkInterfaces.nextElement();
            Enumeration<InetAddress> inetAddresses = nic.getInetAddresses();
            while (inetAddresses.hasMoreElements()) {
                InetAddress address = inetAddresses.nextElement();
                if (address instanceof Inet4Address) {
                    alternatives.addName(new GeneralName(GeneralName.iPAddress, address.getHostAddress()));
                }
            }
        }
        certificate.addExtension(Extension.subjectAlternativeName, false, alternatives.build());

// build BouncyCastle certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keypair.getPrivate());
        X509CertificateHolder holder = certificate.build(signer);

// convert to JRE certificate
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(new BouncyCastleProvider());
        X509Certificate x509 = converter.getCertificate(holder);

        SSLContext sslContext = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        X509Certificate[] chain = {x509};
        keyStore.setKeyEntry("main", keypair.getPrivate(), "654321".toCharArray(), chain);
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, "654321".toCharArray());
        TrustManager[] tm = {new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        sslContext = SSLContext.getInstance("tls");
        sslContext.init(keyManagerFactory.getKeyManagers(), tm, null);


        return sslContext;
    }

    public static void writePem(String pem, String file) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(pem.getBytes("UTF-8"));
        fos.close();
    }
}
