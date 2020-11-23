import cryptolib.ciphers.asymmetric.ECKey;
import cryptolib.ciphers.asymmetric.RSAKey;
import cryptolib.ciphers.symmetric.SymmetricKey;
import cryptolib.core.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class TestUtils {

    public static KeyAuthorizations getKeyAuthorizations(int keySize, PaddingMode paddingMode, BlockMode blockMode, Purpose purpose, Algorithm algorithm) throws NoSuchAlgorithmException {
        KeyAuthorizations keyAuthorizations = new KeyAuthorizations(keySize, algorithm, blockMode, paddingMode, purpose);
        keyAuthorizations.setPurpose(purpose);
        keyAuthorizations.setMacLength(128);
        SecureRandom random = new SecureRandom();
        switch (algorithm){
            case AES:
            case DES:
                SymmetricKey symmetricKey = new SymmetricKey();
                byte[] key = new byte[keySize / 8];
                symmetricKey.setEncodedKey(key);
                byte[] iv = null;
                random.nextBytes(key);
                switch (blockMode){
                    case CBC:
                    case CTR:
                        if(algorithm == Algorithm.AES) {
                            iv = new byte[16];
                        }
                        else{
                            iv = new byte[8];
                        }
                        break;
                    case GCM:
                        iv = new byte[12];
                        break;

                }
                if(iv != null){
                    random.nextBytes(iv);
                    symmetricKey.setIv(iv);
                }
                keyAuthorizations.setKey(symmetricKey);
                break;
            case EC:
                keyAuthorizations.setKey(generateECKey(keyAuthorizations.getKeySize()));
                break;
            case RSA:
                keyAuthorizations.setKey(generateRSAKey(keyAuthorizations.getKeySize()));
                break;
            case HMAC:
                break;
            default:
                break;
        }
        return keyAuthorizations;
    }

    public static RSAKey generateRSAKey(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize * 8);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey();
        rsaKey.setModulus(publicKey.getModulus());
        rsaKey.setPublicExponent(publicKey.getPublicExponent().intValue());
        rsaKey.setPrivateExponent(privateKey.getPrivateExponent());
        return rsaKey;
    }

    public static ECKey generateECKey(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey)keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPrivate();
        ECKey ecKey = new ECKey();
        ecKey.setYPoint(publicKey.getW().getAffineY());
        ecKey.setXPoint(publicKey.getW().getAffineX());
        ecKey.setPrivateField(privateKey.getS());
        return ecKey;
    }
}
