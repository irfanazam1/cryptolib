package ciphers.symmetric;

import com.sun.crypto.provider.SunJCE;
import core.*;
import util.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;

public class AESCipherSuite implements CipherSuite {
    private KeyAuthorizations keyAuthorizations;
    private Cipher cipher;
    public static final int[] AES_KEY_SIZES = {128, 192, 256};
    public static final int GCM_IV_LENGTH = 12;
    public static final int IV_LENGTH = 16;
    private Provider provider;

    @Override
    public KeyAuthorizations getKeyAuthorizations() {
        return keyAuthorizations;
    }

    @Override
    public byte[] update(byte[] input) {
        if(input != null) {
            return cipher.update(input);
        }
        return null;
    }

    @Override
    public byte[] finish(byte[] input) throws BadPaddingException, IllegalBlockSizeException {
        if(input != null && input.length > 0){
            return cipher.doFinal(input);
        }
        return cipher.doFinal();
    }

    @Override
    public int getOutputSize(int length) {
        return cipher.getOutputSize(length);
    }

    @Override
    public byte[] encrypt(byte[] plainBytes){
        try {
            if (plainBytes == null || plainBytes.length == 0) {
                return plainBytes;
            }
            if(getKeyAuthorizations().getPaddingMode() == PaddingMode.NO_PADDING
                && keyAuthorizations.getBlockMode() != BlockMode.GCM) {
                return doNoPaddingCipherOperation(plainBytes, -1);
            }
            else{
                return doCipherOperation(plainBytes, -1);
            }
        }
        catch(Exception ex){
            throw new CryptoLibRuntimeException(ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] cipherBytes, int actualInputLength){
        try {
            if (cipherBytes == null || cipherBytes.length == 0) {
                return cipherBytes;
            }
            if(getKeyAuthorizations().getPaddingMode() == PaddingMode.NO_PADDING
                    && keyAuthorizations.getBlockMode() != BlockMode.GCM) {
                return doNoPaddingCipherOperation(cipherBytes, actualInputLength);
            }
            else{
                return doCipherOperation(cipherBytes, actualInputLength);
            }
        }
        catch(Exception ex){
            throw new CryptoLibRuntimeException(ex);
        }
    }

    public AESCipherSuite(KeyAuthorizations keyAuthorizations)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException {
        this.keyAuthorizations = keyAuthorizations;
        checkKeyAuthorizations();
        initProvider(keyAuthorizations.getProvider());
        initCipherSuite(keyAuthorizations);
    }

    private void initProvider(Provider provider){
        Security.addProvider(provider);
    }

    private void initCipherSuite(KeyAuthorizations keyAuthorizations)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException {

        SymmetricKey key = (SymmetricKey)keyAuthorizations.getKey();
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncodedKey(), keyAuthorizations.getAlgorithm().name());
        int cipherMode;
        if(keyAuthorizations.getPurpose() == Purpose.DECRYPT){
            cipherMode = Cipher.DECRYPT_MODE;
        }
        else if(keyAuthorizations.getPurpose() == Purpose.ENCRYPT){
            cipherMode = Cipher.ENCRYPT_MODE;
        }
        else{
            throw new InvalidAlgorithmParameterException("Cipher Mode not Supported");
        }
        cipher = Cipher.getInstance(Utils.getCipherString(keyAuthorizations.getAlgorithm().name(), keyAuthorizations.getBlockMode().name(),
                keyAuthorizations.getPaddingMode().value()), keyAuthorizations.getProvider().getName());
        AlgorithmParameterSpec algorithmParameterSpec = getAlgorithmParameterSpec(keyAuthorizations.getBlockMode(), key.getIv(), keyAuthorizations.getMacLength());
        if(algorithmParameterSpec != null) {
            cipher.init(cipherMode, keySpec, algorithmParameterSpec);
        }
        else{
            cipher.init(cipherMode, keySpec);
        }
        keyAuthorizations.setBlockSize(cipher.getBlockSize());

    }

    private static AlgorithmParameterSpec getAlgorithmParameterSpec(BlockMode blockMode, byte[] iv, int macLength)
            throws InvalidAlgorithmParameterException {
        if (iv != null && iv.length > 0) {
            switch (blockMode) {
                case GCM:
                    if (iv.length != GCM_IV_LENGTH) {
                        throw new InvalidAlgorithmParameterException("IV Length");
                    }
                    return new GCMParameterSpec(macLength, iv);
                case CBC:
                case CTR:
                    if (iv.length != IV_LENGTH) {
                        throw new InvalidAlgorithmParameterException("IV Length");
                    }
                    return new IvParameterSpec(iv);
            }
        }
        return null;
    }

    private static boolean validateAesKeySize(final int keySizeInBits){
        return Arrays.stream(AES_KEY_SIZES).anyMatch(size -> size == keySizeInBits);
    }

    private byte[] doNoPaddingCipherOperation(byte[] input, int inputLength) throws BadPaddingException, IllegalBlockSizeException {
        List<byte[]> inputChunks = Utils.splitBytesByBlockSizeNoPaddingCipher(input, getKeyAuthorizations().getBlockSize(),
                getKeyAuthorizations().getBlockSize(), getKeyAuthorizations().getBlockMode());
        ByteBuffer buffer = null;
        if(inputLength == - 1) {
            buffer = ByteBuffer.allocate(inputChunks.size() * getKeyAuthorizations().getBlockSize());
        }
        else{
            buffer = ByteBuffer.allocate(getOutputSize(inputLength));
        }
        for(int i = 0; i < inputChunks.size(); i++) {
            byte[] output = update(inputChunks.get(i));
            if (output != null) {
                if (getKeyAuthorizations().getPurpose() == Purpose.ENCRYPT) {
                    buffer.put(output);
                } else if (i < inputChunks.size() - 1) {
                    buffer.put(output);
                } else {
                    int paddingSize = inputChunks.size() * getKeyAuthorizations().getBlockSize() - inputLength;
                    buffer.put(Arrays.copyOfRange(output, paddingSize, output.length));
                }
            }
        }
        byte[] output = finish(null);
        if(output != null){
            buffer.put(output);
        }
        return buffer.array();
    }

    private byte[] doCipherOperation(byte[] input, int inputLength) throws BadPaddingException, IllegalBlockSizeException {
        List<byte[]> inputChunks = Utils.splitBytesByBlockSize(input, getKeyAuthorizations().getBlockSize());
        ByteBuffer buffer = null;
        if(inputLength == -1) {
            buffer = ByteBuffer.allocate(getOutputSize(input.length));
        }
        else if(getKeyAuthorizations().getBlockMode() == BlockMode.GCM){
            buffer = ByteBuffer.allocate(getOutputSize(input.length));
        }
        else{
            buffer = ByteBuffer.allocate(getOutputSize(inputLength));
        }
        for(byte[] in : inputChunks) {
            byte[] output = update(in);
            if(output != null){
                buffer.put(output);
            }
        }
        byte[] output = finish(null);
        if(output != null){
            buffer.put(output);
        }
        if(getKeyAuthorizations().getPurpose() == Purpose.ENCRYPT) {
            return buffer.array();
        }
        else{
            return Arrays.copyOf(buffer.array(), inputLength);
        }
    }

    private void checkKeyAuthorizations(){
        if(!validateAesKeySize(keyAuthorizations.getKeySize())){
            throw new IllegalArgumentException("Key Size not supported");
        }
        if(keyAuthorizations.getKey() == null || !(keyAuthorizations.getKey() instanceof  SymmetricKey)){
            throw new CryptoLibRuntimeException("Symmetric Key is required");
        }
        if(getKeyAuthorizations().getBlockMode() == null){
            throw new CryptoLibRuntimeException("Block Mode is required");
        }
        if(getKeyAuthorizations().getPaddingMode() == null){
            throw new CryptoLibRuntimeException("Padding Mode is required");
        }
        if(getKeyAuthorizations().getPurpose() == null){
            throw new CryptoLibRuntimeException("Purpose is required");
        }
        SymmetricKey symmetricKey = (SymmetricKey)getKeyAuthorizations().getKey();
        if((getKeyAuthorizations().getBlockMode() == BlockMode.CBC
            || getKeyAuthorizations().getBlockMode() == BlockMode.CTR)
            && symmetricKey.getIv() == null){
            throw new CryptoLibRuntimeException("IV is required");
        }
        if((getKeyAuthorizations().getBlockMode() == BlockMode.GCM || getKeyAuthorizations().getBlockMode() == BlockMode.CTR)
            && getKeyAuthorizations().getPaddingMode() != PaddingMode.NO_PADDING){
            throw new CryptoLibRuntimeException("Padding not supported");
        }
    }
}
