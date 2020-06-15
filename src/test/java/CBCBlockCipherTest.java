import ciphers.symmetric.AESCipherSuite;
import ciphers.symmetric.SymmetricKey;
import core.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.Charset;
import java.security.*;
import java.util.Arrays;

public class CBCBlockCipherTest extends BlockCipherTestBase {

    @Test
    public void AESCBC128EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(128, PaddingMode.NO_PADDING, BlockMode.CBC, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESCBC192EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(192, PaddingMode.NO_PADDING, BlockMode.CBC, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESCBC256EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(256, PaddingMode.NO_PADDING, BlockMode.CBC, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESCBC128EncryptDecryptPKCS7PaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(128, PaddingMode.PKCS7_PADDING, BlockMode.CBC, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESCBC192EncryptDecryptPKCS7PaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(192, PaddingMode.PKCS7_PADDING, BlockMode.CBC, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESCBC256EncryptDecryptPKCS7PaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(256, PaddingMode.PKCS7_PADDING, BlockMode.CBC, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

}
