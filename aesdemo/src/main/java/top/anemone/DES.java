package top.anemone;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hello world!
 *
 */

public class DES
{
    public static String charset="ascii";

    public static void main( String[] args ) throws Exception {
        if (args[0].equals("encrypt")){
            System.out.println(encrypt(args[1], args[2]));
        } else if (args[0].equals("decrypt")){
            System.out.println(decrypt(args[1], args[2], args[3]));
        } else {
            System.out.println("Usage:");
            System.out.println("encrypt <plain> <key>");
            System.out.println("decrypt <secret(hex)> <key> <iv(hex)>");
        }
    }
    @SuppressWarnings("all")
    public static String encrypt(String plain, String key) throws Exception {
        byte[] keyBytes = key.getBytes(charset);
        byte[] plainBytes = plain.getBytes(charset);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");//"算法/模式/补码方式"
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(plain.getBytes(charset));
        return bytes2HexStr(iv)+"::"+bytes2HexStr(encrypted);
    }

    @SuppressWarnings("all")
    public static String decrypt(String secret, String key, String iv) throws Exception {
        byte[] keyBytes = key.getBytes(charset);
        byte[] secretBytes = hexStr2Bytes(secret);//先用base64解密
        byte[] ivBytes = hexStr2Bytes(iv);

        IvParameterSpec ivs = new javax.crypto.spec.IvParameterSpec(ivBytes);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivs);
        byte[] plain = cipher.doFinal(secretBytes);
        String plainString = new String(plain,charset);
        return plainString;
    }

    public static byte[] hexStr2Bytes(String hexStr) {
        if (null == hexStr || hexStr.length() < 1) return null;
        int byteLen = hexStr.length() / 2;
        byte[] result = new byte[byteLen];
        char[] hexChar = hexStr.toCharArray();
        for(int i=0 ;i<byteLen;i++){
           result[i] = (byte)(Character.digit(hexChar[i*2],16)<<4 | Character.digit(hexChar[i*2+1],16));
        }
        return result;
    }
    static String bytes2HexStr(byte[] byteArr) {
        if (null == byteArr || byteArr.length < 1) return "";
        StringBuilder sb = new StringBuilder();
        for (byte t : byteArr) {
            if ((t & 0xF0) == 0) sb.append("0");
            sb.append(Integer.toHexString(t & 0xFF));  //t & 0xFF 操作是为去除Integer高位多余的符号位（java数据是用补码表示）
        }
        return sb.toString();
    }
}
