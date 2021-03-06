import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.binary.Hex;
import javax.crypto.Cipher;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.DecoderException;

public class GCMEncriptor {
    private final static int GCM_IV_LENGTH = 12;
    private final static int GCM_TAG_LENGTH = 16;
    
    public static String generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = Hex.encodeHexString(sk.getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return derivedPass;
    }
    
    private static String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }
    
    private static byte[] createIvAndPersistIv() throws IOException {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);
        
        persistIv(iv);
        
        return iv;
    }
    
    
    private static Cipher createCipherInstance(int mode, SecretKey skey, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        cipher.init(mode, skey, ivSpec);
        
        return cipher;
    }
    
    private static byte[] initCipher(Cipher cipher, String message) throws UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        byte[] ciphertext = cipher.doFinal(message.getBytes("UTF8"));
        
        return ciphertext;
    }
    
    private static byte[] readIvFromFile() throws DecoderException, IOException {
        String ivString = readFile("iv.txt").replace("\n", "").replace("\r", "");
        byte[] iv = Hex.decodeHex(ivString.toCharArray());
        
        return iv;
    }
    
    private static byte[] readMessageFromFile(String filename) throws IOException, DecoderException {
        String encryptedMsgString = readFile(filename).replace("\n", "").replace("\r", "");
        byte[] encryptedMsg = Hex.decodeHex(encryptedMsgString.toCharArray());
        
        return encryptedMsg;
    }

    private static void encrypt(String message, SecretKey key, String filename) throws Exception {
        byte[] iv = createIvAndPersistIv();

        Cipher cipher = createCipherInstance(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = initCipher(cipher, message);
        
        writeFile(Hex.encodeHexString(ciphertext), filename);
    }

    private static void decrypt(SecretKey key, String filename) throws Exception {
        byte[] encryptedMsg = readMessageFromFile(filename);
        byte[] iv = readIvFromFile();
        
        byte[] ivAndEncrypted = new byte[iv.length + encryptedMsg.length];
        System.arraycopy(iv, 0, ivAndEncrypted, 0, iv.length);
        System.arraycopy(encryptedMsg, 0, ivAndEncrypted, iv.length, encryptedMsg.length);
        
        Cipher cipher = createCipherInstance(Cipher.DECRYPT_MODE, key, iv);

        byte[] ciphertext = cipher.doFinal(ivAndEncrypted, GCM_IV_LENGTH, ivAndEncrypted.length - GCM_IV_LENGTH);

        String result = new String(ciphertext, "UTF8");
        
        writeFile(result, filename);
    }
    
    private static String readFile (String filename) throws IOException {
        String path = System.getProperty("user.dir") + "/src/";
        File file = new File(path + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        
        String line = null;
        StringBuilder stringBuilder = new StringBuilder();
        String ls = System.getProperty("line.separator");

        try {
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
                stringBuilder.append(ls);
            }
            return stringBuilder.toString();
        } catch (IOException ex) {
            Logger.getLogger(GCMEncriptor.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
                reader.close();
        }
        return null;
    }
    
    private static void writeFile (String txt, String filename) throws IOException{
        String path = System.getProperty("user.dir") + "/src/";
        File file = new File(path + filename);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException ex) {
                Logger.getLogger(GCMEncriptor.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        FileWriter fw = new FileWriter(file.getAbsoluteFile());
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(txt);
        bw.close();
    }
    
    public static byte[] getDecodedKey(String msg) throws NoSuchAlgorithmException {
        String salt = getSalt();
        int it = 10000;
        String chaveDerivada = generateDerivedKey(msg, salt, it);
        byte[] decodedKey = Base64.getDecoder().decode(chaveDerivada);
        
        return decodedKey;
    }
    
    public static SecretKey getSecretKey(byte[] decodedKey) throws NoSuchAlgorithmException {
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
    
    public static void persistKey(byte[] decodedKey) throws IOException {
        writeFile(Hex.encodeHexString(decodedKey), "chave.txt");
    }
    
    public static void persistIv(byte[] iv) throws IOException {
        writeFile(Hex.encodeHexString(iv), "iv.txt");
    }

    public static void main(String[] args) throws Exception {
        // Overwriting Java defaults to support more than 128-bit encryption
        FixJavaKeyLength.fixKeyLength();
        
        String message;
        String filename;
        
        Scanner input = new Scanner(System.in);
        
        System.out.println("Would you like to encript (1) or decript (2)?");
        Integer mode = Integer.parseInt(input.nextLine());
        
        if (mode.equals(1)){
            System.out.println("Please, write down the message you would like to encript: ");
            message = input.nextLine();
            filename = "data.txt";
        
            byte[] decodedKey = getDecodedKey(message);
            SecretKey originalKey = getSecretKey(decodedKey); 
            persistKey(decodedKey);
        
            encrypt(message, originalKey, filename);
            System.out.println("Message encripted successfully!");

        } else if (mode.equals(2)){
            String chaveString = readFile("chave.txt").replace("\n", "").replace("\r", "");
            byte[] chaveBytes = Hex.decodeHex(chaveString.toCharArray());
            SecretKey decryptKey = getSecretKey(chaveBytes);

            decrypt(decryptKey, "data.txt");
            System.out.println("Decripted message available at data.txt");
        } else {
            System.out.println("Unknown Mode");
        }
    }
}