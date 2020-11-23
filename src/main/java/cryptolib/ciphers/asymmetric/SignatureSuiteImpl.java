package cryptolib.ciphers.asymmetric;

import cryptolib.core.*;
import cryptolib.util.Utils;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class SignatureSuiteImpl implements SignatureSuite {
    protected Signature signature;
    protected KeyAuthorizations keyAuthorizations;

    public SignatureSuiteImpl(KeyAuthorizations keyAuthorizations) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.keyAuthorizations = keyAuthorizations;
        initSignature(keyAuthorizations);
    }

    @Override
    public KeyAuthorizations getKeyAuthorizations() {
        return keyAuthorizations;
    }

    @Override
    public void update(byte[] input) throws SignatureException {
        signature.update(input);
    }

    @Override
    public byte[] sign(byte[] plainBytes) throws SignatureException {
        if(plainBytes != null) {
            signature.update(plainBytes);
        }
        return signature.sign();
    }

    @Override
    public boolean verify(byte[] input, byte[] sign) throws SignatureException {
        if(sign == null || sign.length == 0) return false;
        if(input != null && input.length != 0){
            signature.update(input);
        }
        return signature.verify(sign);
    }

    private void initSignature(KeyAuthorizations keyAuthorizations)
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        checkKeyAuthorizations();
        if (keyAuthorizations.getAlgorithm() == Algorithm.RSA) {
            initRSA();
        }
        else if(keyAuthorizations.getAlgorithm() == Algorithm.EC){
            initEC();
        }
    }

    private void initRSA()
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        signature = Signature.getInstance(Utils.getDigestString(keyAuthorizations), keyAuthorizations.getProvider());
        if (keyAuthorizations.getPurpose() == Purpose.SIGN) {
            signature.initSign(getRSAPrivateKey(keyAuthorizations));
        }
        else {
            signature.initVerify(getRSAPublicKey(keyAuthorizations));
        }
    }

    private void initEC() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        X9ECParameters ecCurve = ECNamedCurveTable.getByName(keyAuthorizations.getCurveName());
        ECParameterSpec ecParameterSpec = new ECNamedCurveSpec(keyAuthorizations.getCurveName(), ecCurve.getCurve(), ecCurve.getG(), ecCurve.getN(), ecCurve.getH(), ecCurve.getSeed());
        signature = Signature.getInstance(Utils.getDigestString(keyAuthorizations), keyAuthorizations.getProvider());
        if (keyAuthorizations.getPurpose() == Purpose.SIGN) {
            signature.initSign(getECPrivateKey(keyAuthorizations, ecParameterSpec));
        } else {
            signature.initVerify(getECPublicKey(keyAuthorizations, ecParameterSpec));
        }
    }

    private void checkKeyAuthorizations(){
        if(!(keyAuthorizations.getPurpose() == Purpose.SIGN || keyAuthorizations.getPurpose() == Purpose.VERIFY)){
            throw new CryptoLibRuntimeException("Purpose Not Supported");
        }
        if(keyAuthorizations.getKey() == null) {
            throw new CryptoLibRuntimeException("EncryptionKey");
        }
        if(keyAuthorizations.getAlgorithm() == Algorithm.RSA && !(keyAuthorizations.getKey() instanceof RSAKey)){
            throw new CryptoLibRuntimeException("RSA Key");
        }
        if(keyAuthorizations.getAlgorithm() == Algorithm.EC && !(keyAuthorizations.getKey() instanceof ECKey)){
            throw new CryptoLibRuntimeException("EC Key");
        }
    }

    private static PrivateKey getRSAPrivateKey(KeyAuthorizations keyAuthorizations) throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAKey rsaKey = (RSAKey)keyAuthorizations.getKey();
        BigInteger modulus = new BigInteger(1, rsaKey.getModulus().toByteArray());
        BigInteger privateExponent = new BigInteger(1, rsaKey.getPrivateExponent().toByteArray());
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        return factory.generatePrivate(privateKeySpec);
    }

    private static PublicKey getRSAPublicKey(KeyAuthorizations keyAuthorizations) throws InvalidKeySpecException, NoSuchAlgorithmException {
        RSAKey rsaKey = (RSAKey)keyAuthorizations.getKey();
        BigInteger modulus = new BigInteger(1, rsaKey.getModulus().toByteArray());
        BigInteger publicExponent = BigInteger.valueOf(rsaKey.getPublicExponent());
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        return factory.generatePublic(publicKeySpec);
    }

    private static PublicKey getECPublicKey(KeyAuthorizations keyAuthorizations, ECParameterSpec ecParameterSpec)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECKey ecKey = (ECKey) keyAuthorizations.getKey();
        BigInteger xPoint = new BigInteger(1, ecKey.getXPoint().toByteArray());
        BigInteger yPoint = new BigInteger(1, ecKey.getYPoint().toByteArray());
        ECPoint ecPoint = new ECPoint(xPoint, yPoint);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey getECPrivateKey(KeyAuthorizations keyAuthorizations, ECParameterSpec ecParameterSpec)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECKey ecKey = (ECKey) keyAuthorizations.getKey();
        BigInteger privateField = new BigInteger(1, ecKey.getPrivateField().toByteArray());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateField, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
