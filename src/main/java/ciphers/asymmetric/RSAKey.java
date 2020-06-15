package ciphers.asymmetric;

import core.CryptoKey;

import java.math.BigInteger;

public class RSAKey extends CryptoKey {
    private int publicExponent;
    private BigInteger privateExponent;
    private BigInteger modulus;

    public int getPublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(int publicExponent) {
        this.publicExponent = publicExponent;
    }

    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    public void setPrivateExponent(BigInteger privateExponent) {
        this.privateExponent = privateExponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    @Override
    public int getKeySize() {
        return modulus != null ? (modulus.toByteArray().length * 8) : 0;
    }
}
