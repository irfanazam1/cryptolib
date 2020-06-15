package core;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public interface CipherSuite {
    KeyAuthorizations getKeyAuthorizations();
    byte[] update(byte[] input);
    byte[] finish(byte[] input) throws BadPaddingException, IllegalBlockSizeException;
    int getOutputSize(int length);
    byte[] encrypt(byte[] plainBytes);
    byte[] decrypt(byte[] cipherBytes, int actualInputLength);
}
