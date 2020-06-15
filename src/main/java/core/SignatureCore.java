package core;

public interface SignatureCore {
    public byte[] sign(byte[] input);
    public boolean verify(byte[] input, byte[] signature);
}
