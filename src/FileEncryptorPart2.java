import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Joshua Cook-Harding
 */
public class FileEncryptorPart2 {
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";


    public static void main(String[] args){
        FileEncryptorPart2 fileEncryptor2 = new FileEncryptorPart2();

        byte[] initVector = new byte[16];
        new SecureRandom().nextBytes(initVector);

        if (args.length == 0) {
            fileEncryptor2.input();
        } else {
            switch (args[0]) {  //Used for running through command line, this does not work in part 2 though
                case "enc":
                   //fileEncryptor2.encrypt(args[1], args[2], args[4]); THIS DOESN'T WORK
                    break;
                case "dec":
                    fileEncryptor2.decrypt(args[3], args[2], args[4]);
                    break;
            }
        }

    }

    public void input() {
        label:
        do {
            try {   //Takes the inputs from the user
                System.out.println("Encryptor / Decryptor \nOptions: \nenc - Encrypt file \ndec - Decrypt file \nquit - Quit the program");
                Scanner in = new Scanner(System.in);
                String choice = in.next();
                byte[] salt = new byte[16]; //Creates the salt
                new SecureRandom().nextBytes(salt);


                switch (choice) {   //Input choices
                    case "enc":
                        System.out.println("Encryptor: \nFilename to encrypt, including extension: ");
                        String inputFileName = in.next();
                        System.out.println("Name your file output, no extension needed: ");
                        String outputFileName = in.next();
                        System.out.println("Choose your key for this file: ");
                        String key = in.next();

                        if (!outputFileName.endsWith(".enc")) {
                            outputFileName += ".enc";
                        }

                        System.out.println("Encrypting: " + inputFileName);
                        encrypt(inputFileName, outputFileName, key, salt);
                        System.out.println("Encryption finished, file is saved as: " + outputFileName);
                        continue;

                    case "dec":
                        System.out.println("Decryptor: \nFilename to decrypt, including extension: ");
                        String inputFile = in.next();
                        System.out.println("Base64 secret key: ");
                        key = in.next();
                        String outputFile = "";
                        while (!outputFile.endsWith(".txt")) {
                            System.out.println("Name your file output, followed by \".txt\"");
                            outputFile = in.next();
                            if (!outputFile.endsWith(".txt"))
                                System.err.println("Error. Please ensure the file ends with \".txt\"");
                        }

                        System.out.println("Decryption in progress");
                        decrypt(inputFile, key, outputFile);
                        System.out.println("Decryption finished, file is saved as: " + outputFile);
                        continue;

                    default:
                        System.out.println("Quitting...");
                        break label;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } while (true);
    }


    public void encrypt(String inputPath, String outputPath, String key, byte[] salt){  //This method now takes a salt
        IvParameterSpec iv = new IvParameterSpec(salt);

        byte[] decoder = Base64.getDecoder().decode(key);
        SecretKey secretKey = new SecretKeySpec(decoder, 0, decoder.length, ALGORITHM);
        Cipher cipher = null;

        try {   //Encrypts the cipher into the file
            cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
            InputStream inputFile = new FileInputStream(inputPath);
            OutputStream outputFile = new FileOutputStream(outputPath);
            CipherOutputStream cipherOut = new CipherOutputStream(outputFile, cipher);
            outputFile.write(salt);

            final byte[] bytes = new byte[1024];
            for (int length = inputFile.read(bytes); length != -1; length = inputFile.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
            inputFile.close();
            cipherOut.close();

        } catch (IOException | NullPointerException e) {
            e.printStackTrace();
        }

        System.out.println("Encryption complete. Your encrypted file has been saved at: " + outputPath);
        System.out.println("Please save these keys separately in order to decrypt the file");
        System.out.println("Base64 Secret Key is: " + key);
        System.out.println("Base64 IV is: " + Base64.getEncoder().encodeToString(iv.getIV()));
    }


    public void decrypt(String input, String key, String output){

        byte[] salt = new byte[16]; //Creates the salt
        new SecureRandom().nextBytes(salt);
        byte[] decodedKey = Base64.getDecoder().decode(key);    //Decodes the key


        SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(salt);
        Cipher cipher = null;

        try {   //Extracts the cipher from the encrypted file
            cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
            InputStream encryptedData = new FileInputStream(input);
            OutputStream decryptedOut = new FileOutputStream(output);
            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            decryptStream.read(salt);

            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);

            }
            decryptedOut.close();
            decryptStream.close();

        } catch (IOException | NullPointerException ex) {
            ex.printStackTrace();
        }
        System.out.println("Decryption complete. Your decrypted file has been saved at: " + output);
    }
}
