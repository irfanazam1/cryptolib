package cryptolib.core;

import cryptolib.ciphers.symmetric.AESCipherSuite;
import cryptolib.ciphers.symmetric.DESCipherSuite;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class CipherSuiteFactory {
    private CipherSuiteFactory(){}
    public static CipherSuite getEncryptionSuite(KeyAuthorizations keyAuthorizations)
            throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        if(keyAuthorizations == null){
            throw new CryptoLibRuntimeException("Empty Key Authorizations");
        }
        else if(keyAuthorizations.getAlgorithm() == null){
            throw new CryptoLibRuntimeException("Empty Algorithm");
        }
        switch (keyAuthorizations.getAlgorithm()){
            case AES:
                return new AESCipherSuite(keyAuthorizations);
            case DES:
                return new DESCipherSuite(keyAuthorizations);
            default:
                throw new CryptoLibRuntimeException("Algorithm not implemented yet.");
        }
    }
}
