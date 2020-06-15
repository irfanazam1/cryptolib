package util;

import core.BlockMode;
import org.apache.commons.lang3.StringUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class Utils {

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
            if(blockMode != blockMode.GCM) {
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

}
