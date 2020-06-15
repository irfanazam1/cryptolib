package core;

public interface SignatureCore {
    byte[] sign(byte[] input);
    boolean verify(byte[] input, byte[] signature);
}
