import ciphers.symmetric.AESCipherSuite;
import com.sun.crypto.provider.SunJCE;
import core.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class BlockCipherTestBase {
    protected byte[] plainBytes = "This string will be used to encrypt and/or decrypt".getBytes(Charset.defaultCharset());
    protected void peformChipherOperation(KeyAuthorizations keyAuthorizations) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        keyAuthorizations.setProvider(new BouncyCastleProvider());
        CipherSuite cipherSuite = new AESCipherSuite(keyAuthorizations);
        byte[] cipherBytes = cipherSuite.encrypt(plainBytes);
        keyAuthorizations.setPurpose(Purpose.DECRYPT);
        cipherSuite = new AESCipherSuite(keyAuthorizations);
        byte[] _plainBytes = cipherSuite.decrypt(cipherBytes, plainBytes.length);
        Assertions.assertArrayEquals(plainBytes, _plainBytes);
    }
}
