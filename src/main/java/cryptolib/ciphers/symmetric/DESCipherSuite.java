package cryptolib.ciphers.symmetric;


import cryptolib.core.*;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class DESCipherSuite extends BlockCipherBase {
    private static final int IV_LENGTH = 8;
    protected static final int[] SUPPORTED_KEY_SIZES = {128};
    public DESCipherSuite(KeyAuthorizations keyAuthorizations)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException {
        this.keyAuthorizations = keyAuthorizations;
        checkKeyAuthorizations();
        initProvider(keyAuthorizations.getProvider());
        initCipherSuite(keyAuthorizations);
    }

    @Override
    protected void checkKeyAuthorizations() {
        super.checkKeyAuthorizations();
        if(!validateAesKeySize(keyAuthorizations.getKeySize())){
            throw new IllegalArgumentException("Key Size not supported");
        }
        SymmetricKey symmetricKey = (SymmetricKey) getKeyAuthorizations().getKey();
        if (getKeyAuthorizations().getBlockMode() == BlockMode.GCM || getKeyAuthorizations().getBlockMode() == BlockMode.CTR) {
            throw new CryptoLibRuntimeException("Unsupported Block Mode");
        }
        if (getKeyAuthorizations().getBlockMode() == BlockMode.CBC) {
            if( symmetricKey.getIv() == null) {
                throw new CryptoLibRuntimeException("IV is required");
            }
            else if(symmetricKey.getIv().length != IV_LENGTH){
                throw new CryptoLibRuntimeException("IV length");
            }
        }
        else if (getKeyAuthorizations().getBlockMode() == BlockMode.ECB && symmetricKey.getIv() != null) {
            throw new CryptoLibRuntimeException("IV not supported");
        }

        if (!(getKeyAuthorizations().getPaddingMode() == PaddingMode.NO_PADDING || getKeyAuthorizations().getPaddingMode() == PaddingMode.PKCS5_PADDING)) {
            throw new CryptoLibRuntimeException("Padding not supported");
        }
        byte[] key = null;
        key = Arrays.copyOf(symmetricKey.getEncodedKey(), 8);
        symmetricKey.setEncodedKey(key);
    }

    private static boolean validateAesKeySize(final int keySizeInBits){
        return Arrays.stream(SUPPORTED_KEY_SIZES).anyMatch(size -> size == keySizeInBits);
    }
}
