package cryptolib.util;

import cryptolib.core.*;
import org.apache.commons.lang3.StringUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class Utils {

    private Utils(){}

    public static String getCipherString(String algorithm, String blockMode, String paddingMode){
        StringBuilder cipherStrBuilder = new StringBuilder();
        cipherStrBuilder.append(algorithm);
        if(StringUtils.isNotBlank(blockMode)){
            cipherStrBuilder.append("/").append(blockMode);
        }
        if(StringUtils.isNotBlank(paddingMode)){
            cipherStrBuilder.append("/").append(paddingMode);
        }
        return cipherStrBuilder.toString();
    }

    public static String getPaddingString(PaddingMode paddingMode) {
        switch (paddingMode) {
            case NO_PADDING:
                return "NoPadding";
            case PKCS7_PADDING:
                return "PKCS7Padding";
            case PKCS1_ENCRYPT_PADDING:
                return "PKCS1Padding";
            case OAEP_PADDING:
                return "OAEPPadding";
            case PSS_PADDING:
                return "PSS";
            default:
                return null;

        }
    }

    public static List<byte[]> splitBytesByBlockSizeNoPaddingCipher(byte[] input, int chunkSize, int blockSize, BlockMode blockMode){
        int start = 0;
        int end = input.length;
        List<byte[]> chunks = new ArrayList<>();
        while(start < end){
            ByteBuffer buffer = null;
            if(start + chunkSize <= end) {
                buffer = ByteBuffer.allocate(chunkSize);
                buffer.put(input, start, chunkSize);
            }
            else{
                buffer = ByteBuffer.allocate(end - start);
                buffer.put(input, start, end - start);
            }
            if(blockMode != BlockMode.GCM) {
                byte[] bytes = getLeftZeroPaddedBytes(buffer.array(), blockSize);
                chunks.add(bytes);
            }
            else{
                chunks.add(buffer.array());
            }
            start += chunkSize;
        }
        return chunks;
    }

    public static List<byte[]> splitBytesByBlockSize(byte[] input, int blockSize){
        int start = 0;
        int end = input.length;
        List<byte[]> chunks = new ArrayList<>();
        while(start < end){
            ByteBuffer buffer = null;
            if(start + blockSize <= end) {
                buffer = ByteBuffer.allocate(blockSize);
                buffer.put(input, start, blockSize);
            }
            else{
                buffer = ByteBuffer.allocate(end - start);
                buffer.put(input, start, end - start);

            }
            chunks.add(buffer.array());
            start += blockSize;
        }
        return chunks;
    }

    public static byte[] getLeftZeroPaddedBytes(byte[] input, int paddingLen) {
        if (input.length <= paddingLen) {
            paddingLen = paddingLen - input.length;
        } else {
            paddingLen = paddingLen - (input.length % paddingLen);
        }
        byte[] result = new byte[input.length + paddingLen];
        System.arraycopy(input, 0, result, result.length - input.length, input.length);
        return result;
    }

    public static String getDigestString(KeyAuthorizations keyAuthorizations){
        switch (keyAuthorizations.getAlgorithm()){
            case RSA:
                return getRSADigestName(keyAuthorizations.getDigest(), keyAuthorizations.getPaddingMode());
            case EC:
                return getECDSADigestName(keyAuthorizations.getDigest());
            default:
                return "";
        }
    }

    public static String getRSADigestName(Digest digest, PaddingMode padding) {
        String strPadding = null;
        if (padding == PaddingMode.PSS_PADDING) {
            strPadding = "PSS";
        }
        String strDigest;
        switch (digest) {
            case DIGEST_NONE:
                strDigest = "NONEwithRSA";
                break;
            case SHA1:
                strDigest = "SHA1withRSA";
                break;
            case SHA_2_224:
                strDigest = "SHA224withRSA";
                break;
            case SHA_2_256:
                strDigest = "SHA256withRSA";
                break;
            case SHA_2_384:
                strDigest = "SHA384withRSA";
                break;
            case SHA_2_512:
                strDigest = "SHA512withRSA";
                break;
            case MD5:
                strDigest = "MD5withRSA";
                break;
            default:
                return Digest.DIGEST_UNRECOGNIZED.name();
        }
        return strPadding != null ? String.format("%s/%s", strDigest, strPadding) : strDigest;
    }

    public static String getECDSADigestName(Digest digest) {
        switch (digest) {
            case DIGEST_NONE:
                return "NONEwithECDSA";
            case SHA1:
                return "SHA1withECDSA";
            case SHA_2_224:
                return "SHA224withECDSA";
            case SHA_2_256:
                return "SHA256withECDSA";
            case SHA_2_384:
                return "SHA384withECDSA";
            case SHA_2_512:
                return "SHA512withECDSA";
            case MD5:
                return "MD5withECDSA";
            default:
                return Digest.DIGEST_UNRECOGNIZED.name();
        }
    }

    public static EcCurve getEcCurveFromKeySize(int keySize) {
        switch (keySize) {
            case 224:
                return EcCurve.P_224;
            case 256:
                return EcCurve.P_256;
            case 384:
                return EcCurve.P_384;
            default:
                return EcCurve.P_521;
        }
    }

    public static String getEcCurveName(EcCurve ecCurve) {
        switch (ecCurve) {
            case P_224:
                return "secp224r1";
            case P_256:
                return "secp256r1";
            case P_384:
                return "secp384r1";
            case P_521:
                return "secp521r1";
            default:
                return "";
        }
    }

}
