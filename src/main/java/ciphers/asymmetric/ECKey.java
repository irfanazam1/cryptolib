package ciphers.asymmetric;

import core.CryptoKey;

import java.math.BigInteger;

public class ECKey extends CryptoKey {
    private BigInteger xPoint;
    private BigInteger yPoint;
    private BigInteger privateField;

    public BigInteger getXPoint() {
        return xPoint;
    }

    public void setXPoint(BigInteger xPoint) {
        this.xPoint = xPoint;
    }

    public BigInteger getYPoint() {
        return yPoint;
    }

    public void setYPoint(BigInteger yPoint) {
        this.yPoint = yPoint;
    }

    public BigInteger getPrivateField() {
        return privateField;
    }

    public void setPrivateField(BigInteger privateField) {
        this.privateField = privateField;
    }

    @Override
    public int getKeySize() {
        return xPoint != null ? (xPoint.toByteArray().length * 8) : 0;

    }
}
