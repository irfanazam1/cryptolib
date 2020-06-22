import ciphers.symmetric.SymmetricKey;
import core.*;

import java.security.SecureRandom;

public class TestUtils {

    public static KeyAuthorizations getKeyAuthorizations(int keySize, PaddingMode paddingMode, BlockMode blockMode, Purpose purpose, Algorithm algorithm){
        KeyAuthorizations keyAuthorizations = new KeyAuthorizations(keySize, algorithm, blockMode, paddingMode, purpose);
        keyAuthorizations.setPurpose(purpose);
        keyAuthorizations.setMacLength(128);
        SecureRandom random = new SecureRandom();
        switch (algorithm){
            case AES:
            case DES:
                SymmetricKey symmetricKey = new SymmetricKey();
                byte[] key = new byte[keySize / 8];
                symmetricKey.setEncodedKey(key);
                byte[] iv = null;
                random.nextBytes(key);
                switch (blockMode){
                    case CBC:
                    case CTR:
                        if(algorithm == Algorithm.AES) {
                            iv = new byte[16];
                        }
                        else{
                            iv = new byte[8];
                        }
                        break;
                    case GCM:
                        iv = new byte[12];
                        break;

                }
                if(iv != null){
                    random.nextBytes(iv);
                    symmetricKey.setIv(iv);
                }
                keyAuthorizations.setKey(symmetricKey);
                break;
            case EC:
                break;
            case RSA:
                break;
            case HMAC:
                break;
            default:
                break;
        }
        return keyAuthorizations;
    }
}
