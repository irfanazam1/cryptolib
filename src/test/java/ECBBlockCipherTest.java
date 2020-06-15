import core.*;
import org.junit.jupiter.api.Test;

public class ECBBlockCipherTest extends BlockCipherTestBase {

    @Test
    public void AESECB128EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(128, PaddingMode.NO_PADDING, BlockMode.ECB, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESECB192EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(192, PaddingMode.NO_PADDING, BlockMode.ECB, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESECB256EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(256, PaddingMode.NO_PADDING, BlockMode.ECB, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESECB128EncryptDecryptPKCS7PaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(128, PaddingMode.PKCS7_PADDING, BlockMode.ECB, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESECB192EncryptDecryptPKCS7PaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(192, PaddingMode.PKCS7_PADDING, BlockMode.ECB, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESECB256EncryptDecryptPKCS7PaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(256, PaddingMode.PKCS7_PADDING, BlockMode.ECB, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

}
