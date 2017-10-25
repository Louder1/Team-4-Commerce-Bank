package Entity;

import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;


public class Crypto {

    private String textToEncrypt,textToDecrypt;
    final static String password = "Hello";

    public String Encrypt(String textToEncrypt, String salt)
    {
        if (textToEncrypt != null && !textToEncrypt.isEmpty())
        {
            TextEncryptor encryptor = Encryptors.text(password, salt);
            String encryptedText = encryptor.encrypt(textToEncrypt);
            return encryptedText;
        }

        return null;
    }

    public String Decrypt(String textToDecrypt,String salt)
    {
        if(textToDecrypt != null && !textToDecrypt.isEmpty())
        {
            TextEncryptor decryptor = Encryptors.text(password,salt);
            String decryptedText = decryptor.decrypt(textToDecrypt);
            return decryptedText;
        }
        return null;
    }


    public String getTextToEncrypt() { return textToEncrypt; }
}
