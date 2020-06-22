package ciphers.symmetric;

import core.*;
import util.Utils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class AESCipherSuite extends BlockCipherBase {
    private static final int GCM_IV_LENGTH = 12;
    private static final int IV_LENGTH = 16;
    public static final int[] SUPPORTED_KEY_SIZES = {128, 192, 256};
    public AESCipherSuite(KeyAuthorizations keyAuthorizations)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException {
        this.keyAuthorizations = keyAuthorizations;
        checkKeyAuthorizations();
        initProvider(keyAuthorizations.getProvider());
        initCipherSuite(keyAuthorizations);
    }

    protected void checkKeyAuthorizations(){
        super.checkKeyAuthorizations();
        if(!validateAesKeySize(keyAuthorizations.getKeySize())){
            throw new IllegalArgumentException("Key Size not supported");
        }
        SymmetricKey symmetricKey = (SymmetricKey)getKeyAuthorizations().getKey();
        if(getKeyAuthorizations().getBlockMode() == BlockMode.ECB && symmetricKey.getIv() != null){
            throw new CryptoLibRuntimeException("IV not supported");
        }
        if((getKeyAuthorizations().getBlockMode() == BlockMode.CBC
            || getKeyAuthorizations().getBlockMode() == BlockMode.CTR)
            && symmetricKey.getIv() == null){
            throw new CryptoLibRuntimeException("IV is required");
        }
        if((getKeyAuthorizations().getBlockMode() == BlockMode.GCM || getKeyAuthorizations().getBlockMode() == BlockMode.CTR)
            && getKeyAuthorizations().getPaddingMode() != PaddingMode.NO_PADDING){
            throw new CryptoLibRuntimeException("Padding not supported");
        }
        if (symmetricKey.getIv() != null && symmetricKey.getIv().length > 0) {
            switch (getKeyAuthorizations().getBlockMode()) {
                case GCM:
                    if (symmetricKey.getIv().length != GCM_IV_LENGTH) {
                        throw new CryptoLibRuntimeException("IV Length");
                    }
                    break;
                case CBC:
                case CTR:
                    if (symmetricKey.getIv().length != IV_LENGTH) {
                        throw new CryptoLibRuntimeException("IV Length");
                    }
                    break;
            }
        }
    }

    private static boolean validateAesKeySize(final int keySizeInBits){
        return Arrays.stream(SUPPORTED_KEY_SIZES).anyMatch(size -> size == keySizeInBits);
    }
}
