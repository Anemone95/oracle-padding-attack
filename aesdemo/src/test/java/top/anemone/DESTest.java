package top.anemone;

import static org.junit.Assert.assertTrue;
import static top.anemone.DES.decrypt;
import static top.anemone.DES.encrypt;

import org.junit.Test;

/**
 * Unit test for simple DES.
 */
public class DESTest
{
    /**
     * Rigorous Test :-)
     */
    @Test
    public void encryptTest() throws Exception {
        String plain="12345678";
        String key="keykeyke";
        String secret=encrypt(plain, key);
        System.out.println(secret);
        assertTrue( true );
    }

    @Test
    public void decryptTest() throws Exception {
        String key="keykeyke";
        String secret2="11c3d5b9ebce543891eb68e9a78b729f";
        String iv="96b61b2d0de0a0b4";
        String decodePlain=decrypt(secret2,key,iv);
        System.out.println(decodePlain);
    }
}
