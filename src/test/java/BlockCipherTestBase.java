import cryptolib.core.CipherSuite;
import cryptolib.core.CipherSuiteFactory;
import cryptolib.core.KeyAuthorizations;
import cryptolib.core.Purpose;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class BlockCipherTestBase {
    protected final byte[] plainBytes = "This string will be used to encrypt and/or decrypt".getBytes(Charset.defaultCharset());
    protected void peformChipherOperation(KeyAuthorizations keyAuthorizations) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        keyAuthorizations.setProvider(new BouncyCastleProvider());
        CipherSuite cipherSuite = CipherSuiteFactory.getEncryptionSuite(keyAuthorizations);
        byte[] cipherBytes = cipherSuite.encrypt(plainBytes);
        keyAuthorizations.setPurpose(Purpose.DECRYPT);
        cipherSuite = CipherSuiteFactory.getEncryptionSuite(keyAuthorizations);
        byte[] _plainBytes = cipherSuite.decrypt(cipherBytes, plainBytes.length);
        Assert.assertEquals(Arrays.toString(plainBytes), Arrays.toString(_plainBytes));
    }
}
