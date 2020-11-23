import cryptolib.ciphers.asymmetric.SignatureSuiteImpl;
import cryptolib.core.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.Charset;

public class RSASignatureTest {
    static byte[] plainText = "String to be signed".getBytes(Charset.defaultCharset());
    Digest[] digests = new Digest[]{
            Digest.DIGEST_NONE,
            Digest.SHA1,
            Digest.SHA_2_256,
            Digest.SHA_2_384,
            Digest.SHA_2_512
    };
    int[] sizes = new int[]{ 256 }; //, 384, 512}; UnComment to test the other key sizes. This has been done to make the test run quickly.
    PaddingMode[] paddingModes = new PaddingMode[]{
            PaddingMode.NO_PADDING,
            PaddingMode.PKCS1_SIGN_PADDING,
            PaddingMode.PKCS7_PADDING
    };
    @Test
    public void RSASignatureTest() throws Exception{
        for(int keySize : sizes){
            for(Digest digest : digests){
                for(PaddingMode paddingMode : paddingModes){
                    KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(keySize, paddingMode, BlockMode.ECB, Purpose.SIGN, Algorithm.RSA);
                    keyAuthorizations.setProvider(new BouncyCastleProvider());
                    keyAuthorizations.setDigest(digest);
                    SignatureSuite signatureSuite = new SignatureSuiteImpl(keyAuthorizations);
                    byte[] sign = signatureSuite.sign(plainText);
                    keyAuthorizations.setPurpose(Purpose.VERIFY);
                    signatureSuite = new SignatureSuiteImpl(keyAuthorizations);
                    Assert.assertTrue(signatureSuite.verify(plainText, sign));
                }
            }
        }
    }
}
