import cryptolib.core.*;
import org.junit.Test;


public class TrippleDESBlockCipherTest extends BlockCipherTestBase {

    @Test
    public void TrippleDESCBC128EncryptDecryptNoPaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(128, PaddingMode.NO_PADDING, BlockMode.CBC, Purpose.ENCRYPT, Algorithm.DES);
        peformChipherOperation(keyAuthorizations);
    }

    @Test
    public void TrippleDESCBC128EncryptDecryptPKCS5PaddingTest() throws Exception{
        KeyAuthorizations keyAuthorizations = TestUtils.getKeyAuthorizations(128, PaddingMode.PKCS5_PADDING, BlockMode.CBC, Purpose.ENCRYPT, Algorithm.DES);
        peformChipherOperation(keyAuthorizations);
    }

}
