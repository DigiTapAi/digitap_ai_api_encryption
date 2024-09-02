import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JweEncryption {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String jweEncrypt(String publicKeyPem, String payload) throws Exception {
        PublicKey publicKey = loadPublicKey(publicKeyPem);

        // Create RSA key from the public key
        RSAKey rsaKey = new RSAKey.Builder(publicKey).build();

        // Create the JWE header and specify:
        // RSA-OAEP-256 as the encryption algorithm
        // A256GCM as the content encryption algorithm
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("text/plain")
                .build();

        // Create the JWE object and encrypt it
        Payload jwePayload = new Payload(payload);
        JWEObject jweObject = new JWEObject(header, jwePayload);

        RSAEncrypter encrypter = new RSAEncrypter(rsaKey);
        jweObject.encrypt(encrypter);

        // Serialize to compact form
        return jweObject.serialize();
    }

    public static String jweDecrypt(String privateKeyPem, String jweEncryptedPayload) throws Exception {
        PrivateKey privateKey = loadPrivateKey(privateKeyPem);

        // Parse the JWE string
        JWEObject jweObject = JWEObject.parse(jweEncryptedPayload);

        // Decrypt the JWE
        RSADecrypter decrypter = new RSADecrypter(privateKey);
        jweObject.decrypt(decrypter);

        // Extract the payload
        return jweObject.getPayload().toString();
    }

    private static PublicKey loadPublicKey(String pem) throws Exception {
        String publicKeyPEM = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey loadPrivateKey(String pem) throws Exception {
        String privateKeyPEM = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }

    public static void main(String[] args) {
        try {
            // Load public and private keys from PEM files
            String publicKeyPem = new String(Files.readAllBytes(new File("public_key.pem").toPath()));
            String privateKeyPem = new String(Files.readAllBytes(new File("private_key.pem").toPath()));

            // Sample payload to encrypt
            String requestPayload = "{\"pan\":\"\", \"client_ref_num\":\"jwe-encryption-test\"}";

            // Encrypt the payload
            String encryptedJwe = jweEncrypt(publicKeyPem, requestPayload);
            System.out.println("Encrypted JWE: " + encryptedJwe);

            // Simulate sending an encrypted request payload
            String encryptedRequestPayload = "{\"encrypted_data\":\"" + encryptedJwe + "\"}";

            // Simulate receiving a response (decrypt the payload)
            String decryptedPayload = jweDecrypt(privateKeyPem, encryptedJwe);
            System.out.println("Decrypted Payload: " + decryptedPayload);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
