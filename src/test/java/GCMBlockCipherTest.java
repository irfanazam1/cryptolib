import core.*;
import org.junit.jupiter.api.Test;

public class GCMBlockCipherTest extends BlockCipherTestBase {

    @Test
    public void AESGCM128EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(128, PaddingMode.NO_PADDING, BlockMode.GCM, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESGCM192EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(192, PaddingMode.NO_PADDING, BlockMode.GCM, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void AESGCM256EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(256, PaddingMode.NO_PADDING, BlockMode.GCM, Purpose.ENCRYPT, Algorithm.AES);
        peformChipherOperation(keyAuthorizations);
    }

}
