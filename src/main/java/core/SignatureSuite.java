package core;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public interface SignatureSuite {
    KeyAuthorizations getKeyAuthorizations();
    byte[] update(byte[] input);
    byte[] finish(byte[] input) throws BadPaddingException, IllegalBlockSizeException;
    byte[] sign(byte[] plainBytes);
    boolean verify(byte[] input, byte[] signature);
}
