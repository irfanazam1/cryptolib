package cryptolib.core;

import com.sun.crypto.provider.SunJCE;

import java.security.Provider;

public class KeyAuthorizations {
    private int keySize;
    private BlockMode blockMode = BlockMode.ECB;
    private PaddingMode paddingMode = PaddingMode.NO_PADDING;
    private Algorithm algorithm = Algorithm.ALGORITHM_UNRECOGNIZED;
    private CryptoKey key;
    private Purpose purpose = Purpose.PURPOSE_UNRECOGNIZED;
    private int macLength;
    private int blockSize;
    private Provider provider = new SunJCE();
    private Digest digest = Digest.DIGEST_UNRECOGNIZED;
    private String curveName;
    public KeyAuthorizations(int keySize, Algorithm algorithm, BlockMode blockMode, PaddingMode paddingMode, Purpose purpose){
        this.keySize = keySize;
        this.algorithm = algorithm;
        this.blockMode = blockMode;
        this.paddingMode = paddingMode;
        this.purpose = purpose;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public CryptoKey getKey() {
        return key;
    }

    public void setKey(CryptoKey key) {
        this.key = key;
    }

    public BlockMode getBlockMode() {
        return blockMode;
    }

    public void setBlockMode(BlockMode blockMode) {
        this.blockMode = blockMode;
    }

    public PaddingMode getPaddingMode() {
        return paddingMode;
    }

    public void setPaddingMode(PaddingMode paddingMode) {
        this.paddingMode = paddingMode;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    public Purpose getPurpose() {
        return purpose;
    }

    public void setPurpose(Purpose purpose) {
        this.purpose = purpose;
    }

    public int getMacLength() {
        return macLength;
    }

    public void setMacLength(int macLength) {
        this.macLength = macLength;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = blockSize;
    }

    public Provider getProvider() {
        return provider;
    }

    public void setProvider(Provider provider) {
        this.provider = provider;
    }

    public Digest getDigest(){
        return digest;
    }

    public void setDigest(Digest digest){
        this.digest = digest;
    }

    public String getCurveName() {
        return curveName;
    }

    public void setCurveName(String curveName) {
        this.curveName = curveName;
    }
}
