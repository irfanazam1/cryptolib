package cryptolib.core;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.SignatureException;

public interface CipherSuite {
    KeyAuthorizations getKeyAuthorizations();
    byte[] update(byte[] input) throws SignatureException;
    byte[] finish(byte[] input) throws BadPaddingException, IllegalBlockSizeException, SignatureException;
    int getOutputSize(int length);
    byte[] encrypt(byte[] plainBytes);
    byte[] decrypt(byte[] cipherBytes, int actualInputLength);
}
