package core;

import org.apache.commons.lang3.StringUtils;
import util.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class EncryptionCore {
    private CipherSuite cipherSuite;

    public byte[] encrypt(byte[] plainBytes){
        try {
            if (plainBytes == null || plainBytes.length == 0) {
                return plainBytes;
            }
            return doCipherOperation(plainBytes, -1);
        }
        catch(Exception ex){
            throw new CryptoLibRuntimeException(ex);
        }
    }

    public byte[] decrypt(byte[] cipherBytes, int actualInputLength){
        try {
            if (cipherBytes == null || cipherBytes.length == 0) {
                return cipherBytes;
            }
            return doCipherOperation(cipherBytes, actualInputLength);
        }
        catch(Exception ex){
            throw new CryptoLibRuntimeException(ex);
        }
    }

    public String encrypt(String plainText){
        if(StringUtils.isBlank(plainText)){
            return null;
        }
        byte[] plainBytes = plainText.getBytes(Charset.forName("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypt(plainBytes));
    }

    public String decrypt(String cipherText, int actualInputLength){
        if(StringUtils.isBlank(cipherText)){
            return null;
        }
        byte[] cipherBytes = cipherText.getBytes(Charset.forName("UTF-8"));
        return Base64.getEncoder().encodeToString(decrypt(cipherBytes, actualInputLength));
    }

    public EncryptionCore(CipherSuite cipherSuite){
        this.cipherSuite = cipherSuite;
    }

    private byte[] doCipherOperation(byte[] input, int inputLength) throws BadPaddingException, IllegalBlockSizeException {
        List<byte[]> inputChunks = Utils.splitBytesByBlockSizeNoPaddingCipher(input, cipherSuite.getKeyAuthorizations().getBlockSize(),
                cipherSuite.getKeyAuthorizations().getBlockSize(), cipherSuite.getKeyAuthorizations().getBlockMode());
        ByteBuffer buffer = null;
        if(inputLength == - 1) {
            buffer = ByteBuffer.allocate(inputChunks.size() * cipherSuite.getKeyAuthorizations().getBlockSize());
        }
        else{
            buffer = ByteBuffer.allocate(cipherSuite.getOutputSize(inputLength));
        }
        for(int i = 0; i < inputChunks.size(); i++) {
            byte[] output = cipherSuite.update(inputChunks.get(i));
            if (output != null) {
                if (cipherSuite.getKeyAuthorizations().getPurpose() == Purpose.ENCRYPT) {
                    buffer.put(output);
                } else if (i < inputChunks.size() - 1) {
                    buffer.put(output);
                } else {
                    int paddingSize = inputChunks.size() * cipherSuite.getKeyAuthorizations().getBlockSize() - inputLength;
                    buffer.put(Arrays.copyOfRange(output, paddingSize, output.length));
                }
            }
        }
        byte[] output = cipherSuite.finish(null);
        if(buffer.array().length + output.length < buffer.capacity()){
            buffer.put(output);
        }
        return buffer.array();
    }
}
