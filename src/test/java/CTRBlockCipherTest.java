
import cryptolib.core.*;
import org.junit.Test;

public class CTRBlockCipherTest extends BlockCipherTestBase {

    @Test
    public void AESCTR128EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(128, PaddingMode.NO_PADDING, BlockMode.CTR, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESCTR192EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(192, PaddingMode.NO_PADDING, BlockMode.CTR, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESCTR256EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(256, PaddingMode.NO_PADDING, BlockMode.CTR, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

}
