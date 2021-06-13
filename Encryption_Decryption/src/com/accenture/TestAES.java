package com.accenture;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

public class TestAES {

	public static void encryptAndStore() throws FileNotFoundException, IOException
	{
		Properties prop1=new Properties();
    	prop1.load(new FileInputStream("credentials.properties"));
    	String user=prop1.getProperty("user");
    	String pass=prop1.getProperty("password");
  
    	// We are setting the secket key in the environment variable of the system
    	String key=System.getenv("secretkey");
    	
		
    	String encrypteduser=AES.encrypt(user,key);
		String encryptedpassword=AES.encrypt(pass,key);
		
		
		Properties prop2=new Properties();
    	prop2.put("euser",encrypteduser);
    	prop2.put("epass",encryptedpassword);
    //	prop2.put("secretkey",key);
    	
    	prop2.store(new FileOutputStream("encryptedCredentials.properties",true),"This is a encrypted credentials");
    	System.out.println("Files are encrypted and stored to file.");

	}
	
	
	public static void decrypt() throws FileNotFoundException, IOException
	{
		Properties prop1=new Properties();
    	prop1.load(new FileInputStream("encryptedCredentials.properties"));
    	String euser=prop1.getProperty("euser");
    	String epass=prop1.getProperty("epass");
    	
    	//We are setting the secket key in the environment variable of the system.
    	String secretkey=System.getenv("secretkey");
    	
    	String decrypteduser=AES.decrypt(euser, secretkey);
    	String decryptedpass=AES.decrypt(epass, secretkey);
    	
		System.out.println("the decrypted credentials are : \nuser :"+decrypteduser+"\npassword : "+decryptedpass);
		
	}
	public static void main(String[] args) throws FileNotFoundException, IOException {
		
	TestAES.encryptAndStore();
		TestAES.decrypt();
	}

}
