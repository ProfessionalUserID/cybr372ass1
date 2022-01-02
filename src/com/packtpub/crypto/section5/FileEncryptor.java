package com.packtpub.crypto.section5;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Joshua Cook-Harding
 */
public class FileEncryptor {
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        FileEncryptor fileEncryptor = new FileEncryptor();
        if (args.length == 0) {
            fileEncryptor.input();
        }
        else {
            switch (args[0]) {  //Used to run through the command line
                case "enc":
                    fileEncryptor.encrypt(args[1], args[2]);
                    break;
                case "dec":
                    fileEncryptor.decrypt(args[3], Base64.getDecoder().decode(args[2]), Base64.getDecoder().decode(args[1]), args[4]);
                    break;
            }
        }
    }

    public void input() {   //Takes the inputs of the user
        label:
        do {
            try {
                System.out.println("Encryptor / Decryptor \nOptions: \nenc - Encrypt file \ndec - Decrypt file \nquit - Quit the program");
                Scanner in = new Scanner(System.in);
                String choice = in.next();

                switch (choice) {   //Input choices
                    case "enc": //If encryption is selected
                        System.out.println("Encryptor: \nFilename to encrypt, including extension: ");
                        String inputFileName = in.next();
                        System.out.println("Name your file output, no extension needed: ");
                        String outputFileName = in.next();

                        if (!outputFileName.endsWith(".enc")) {
                            outputFileName += ".enc";
                        }

                        System.out.println("Encrypting: "+inputFileName);
                        encrypt(inputFileName, outputFileName);
                        System.out.println("Encryption finished, file is saved as: " + outputFileName);
                        continue;

                    case "dec":   //If decryption is selected
                        System.out.println("Decryptor: \nFilename to decrypt, including extension: ");
                        String inputFile = in.next();
                        System.out.println("Base64 secret key: ");
                        String key = in.next();
                        System.out.println("Base64 IV: ");
                        String initVector = in.next();
                        String outputFile = "";
                        while (!outputFile.endsWith(".txt")) {  //Loops in case the used forgets the ".txt" at the end
                            System.out.println("Name your file output, followed by \".txt\"");
                            outputFile = in.next();
                            if (!outputFile.endsWith(".txt")) System.err.println("Error. Please ensure the file ends with \".txt\"");
                        }
                            System.out.println("Decryption in progress");
                            decrypt(inputFile, Base64.getDecoder().decode(key), Base64.getDecoder().decode(initVector), outputFile);
                            System.out.println("Decryption finished, file is saved as: " + outputFile);
                            continue;

                    default:    //Quits the program
                        System.out.println("Quitting...");
                        break label;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } while (true);
    }

    public static IvParameterSpec generateIV() {    //Generates an inital vector
        byte[] initVector = new byte[16];
        new SecureRandom().nextBytes(initVector);
        return new IvParameterSpec(initVector);
    }

    public static byte[] generateKey() {    //Generates a key
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        return key;
    }

    public void encrypt(String inputPath, String outputPath) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        byte[] key = generateKey();
        IvParameterSpec iv = FileEncryptor.generateIV();

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        try {
            InputStream inputFile = new FileInputStream(inputPath);
            OutputStream outputFile = new FileOutputStream(outputPath);
            CipherOutputStream cipherOut = new CipherOutputStream(outputFile, cipher);

            final byte[] bytes = new byte[1024];
            for (int length = inputFile.read(bytes); length != -1; length = inputFile.read(bytes)) {    //Loops to read the file
                cipherOut.write(bytes, 0, length);
            }

            inputFile.close();
            cipherOut.close();

        } catch (IOException | NullPointerException e) {
            e.printStackTrace();
        }

        System.out.println("Encryption complete. Your encrypted file has been saved at: " + outputPath);
        System.out.println("Please save these keys separately in order to decrypt the file");
        System.out.println("Base64 Secret Key is: " + Base64.getEncoder().
                encodeToString(key));
        System.out.println("Base64 IV is: " + Base64.getEncoder().
                encodeToString(iv.getIV()));
    }


    public void decrypt(String input, byte[] key, byte[] initVector, String output) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        try {
            InputStream encryptedData = new FileInputStream(input);
            OutputStream decryptedOut = new FileOutputStream(output);
            CipherOutputStream decryptStream = new CipherOutputStream(decryptedOut, cipher);

            final byte[] bytes = new byte[1024];
            for (int length = encryptedData.read(bytes); length != -1; length = encryptedData.read(bytes)) {    //Loops to read the file
                decryptStream.write(bytes, 0, length);
            }

            encryptedData.close();
            decryptStream.close();

        } catch (IOException | NullPointerException ex) {
            ex.printStackTrace();
        }
        System.out.println("Decryption complete. Your decrypted file has been saved at: " + output);
    }
}
