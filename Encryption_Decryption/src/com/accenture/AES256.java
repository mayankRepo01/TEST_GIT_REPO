package com.accenture;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AES256 {
	private static final IvParameterSpec iv;
	private static final String algorithm = "AES/CBC/PKCS5Padding";
	
	static {
		iv=generateIv();
	}
	
	/*
	For generating a secret key, we can use the KeyGenerator class. Let’s define a method for 
	generating the AES key with the size of n (128, 192, and 256) bits:
	*/
	private static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
	    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	    keyGenerator.init(n);
	    SecretKey key = keyGenerator.generateKey();
	    return key;
	}

	/*
	 * IV is a pseudo-random value and has the same size as the block that is encrypted.
	 * We can use the SecureRandom class to generate a random IV.
	 */
	 
	 private static IvParameterSpec generateIv() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return new IvParameterSpec(iv);
	}
	
	
	/*
	 * we create an instance from the Cipher class by using the getInstance() method.
	 * we configure a cipher instance using the init() method with a secret key, IV, and encryption mode.
	 * Finally, we encrypt the input string by invoking the doFinal() method.
	 *  This method gets bytes of input and returns ciphertext in bytes:
	 * */
	private static String encryptUtil(String input, String algorithm,SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
		    InvalidAlgorithmParameterException, InvalidKeyException,
		    BadPaddingException, IllegalBlockSizeException {
		    
			Cipher cipher = Cipher.getInstance(algorithm);
		    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		    byte[] cipherText = cipher.doFinal(input.getBytes());
		    return Base64.getEncoder().encodeToString(cipherText);
		}
	
	
	
	//For decryption an input string, we can initialize our cipher using the DECRYPT_MODE to decrypt the content:

		private static String decryptUtil(String cipherText, String algorithm,  SecretKey key,
		    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
		    InvalidAlgorithmParameterException, InvalidKeyException,
		    BadPaddingException, IllegalBlockSizeException {
		    
		    Cipher cipher = Cipher.getInstance(algorithm);
		    cipher.init(Cipher.DECRYPT_MODE, key, iv);
		    byte[] plainText = cipher.doFinal(Base64.getDecoder()
		        .decode(cipherText));
		    return new String(plainText);
		}
		
		public static String encrypt(String PlainText, SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException{
	
			
			return encryptUtil(PlainText, algorithm, key, iv);
		}
		public static String decrypt(String cipherText,SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException{
	
			
			return decryptUtil(cipherText, algorithm, key, iv);
		}
		
		public static void main(String args[]) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException{
			
			String PlainText="Mayank.mishra";
			 SecretKey key=generateKey(256);
			
			 //---------------------------------------------------------------------------------
			 String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
//			 
			 System.out.println(encodedKey);
			 
			 
			// decode the base64 encoded string
			 byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
			 // rebuild key using SecretKeySpec
			// SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
			 
		//	 --------------------------------------------------------------------------------
			 //UPKJSjlgrL3H1UhwR6Rw1VYaOUrXvi+pkICRdT/OtE8=
			 
//			String cipher=encrypt(PlainText,key);
//			
//			System.out.println("This is the Plain text : \t"+PlainText);
//			System.out.println("This is the cipher text : \t"+cipher);
//			
//			String decriptedtext=decrypt(cipher,key);
//			System.out.println("This is the decrypted text : \t"+decriptedtext);
//			//FW+YEcJfNmfRifW5/JiWew==
//			
			
		}
		
}
		