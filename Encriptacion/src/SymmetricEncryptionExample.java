import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionExample {

    public static void main(String[] args) throws Exception {
        // Generar una clave secreta
        // Clave personalizada (debe tener 16, 24 o 32 bytes para AES-128, AES-192 o AES-256, respectivamente)
        String clavePersonalizada = "claveSecreta1234";

        // Convertir la clave a bytes
        byte[] claveBytes = clavePersonalizada.getBytes();

        // Crear una instancia de SecretKeySpec con la clave
        SecretKey secretKey = new SecretKeySpec(claveBytes, "AES");

        //Simulamos el error
        String claveFalsa = "clavePirata99999";
        SecretKey secretKeyFalsa = new SecretKeySpec(claveFalsa.getBytes(), "AES");

        // Mensaje a cifrar
        String message = "Hola, este es un mensaje secreto";

        // Cifrar el mensaje
        byte[] encryptedMessage = encrypt(message, secretKey);

        System.out.println("Mensaje cifrado: " + Base64.getEncoder().encodeToString(encryptedMessage));

        // Descifrar el mensaje
        //String decryptedMessage = decrypt(encryptedMessage, secretKey);

        // Intentamos descifrar usando la clave FALSA
        String decryptedMessage = decrypt(encryptedMessage, secretKeyFalsa);
        System.out.println("Mensaje descifrado: " + decryptedMessage);
    }

    public static byte[] encrypt(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message.getBytes());
    }

    public static String decrypt(byte[] encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }
}
