package cryptolib.ciphers.symmetric;

import cryptolib.core.CryptoKey;

public class SymmetricKey extends CryptoKey {

    private byte[] encodedKey;
    private byte[] iv;

    public byte[] getEncodedKey() {
        return encodedKey;
    }

    public void setEncodedKey(byte[] encoded) {
        this.encodedKey = encoded;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    @Override
    public int getKeySize() {
        return encodedKey != null ? (encodedKey.length * 8) : 0;
    }

}
