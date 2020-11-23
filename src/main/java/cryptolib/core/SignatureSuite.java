package cryptolib.core;

import java.security.SignatureException;

public interface SignatureSuite{
    byte[] sign(byte[] plainBytes) throws SignatureException;
    boolean verify(byte[] input, byte[] signature) throws SignatureException;
    void update(byte[] input) throws SignatureException;
    KeyAuthorizations getKeyAuthorizations();
}
