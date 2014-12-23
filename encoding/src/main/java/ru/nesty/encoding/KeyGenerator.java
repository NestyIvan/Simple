package ru.nesty.encoding;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyGenerator {
	private final String workingDir;
	private final String passPhrase;
	private final Integer keySize = 2048;
	
	public KeyGenerator(String workingDir, String passPhrase){
		this.workingDir = workingDir;
		this.passPhrase = passPhrase;
	}
	
	public static void main(String[] args) {
		KeyGenerator kg = new KeyGenerator(args[0], args[1]);
		kg.genKeyPair();
	}
	
	/** updKEyPair genKeyPair Generate new pair of key </br>
	 * */
	public void genKeyPair() {		
        KeyPairGenerator kg;
		try {
			kg = KeyPairGenerator.getInstance("RSA");//throws NoSuchAlgorithmException
	        kg.initialize(keySize);	        
	        KeyPair pair = kg.generateKeyPair();	        
	        SaveKeyPair(workingDir, pair, passPhrase);//throws Exception          		
		} catch (NoSuchAlgorithmException e) {			
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}        
	}
	
	private  void SaveKeyPair(String path, KeyPair pair, String passphrase) {
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();
		
		File fldr = new File(path);
		if (fldr.exists() == false)
			fldr.mkdir();
		
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(path + "/key.pub");//throws FileNotFoundException
			fos.write(x509EncodedKeySpec.getEncoded());//throws IOException
			fos.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		try {
			fos = new FileOutputStream(path + "/key.pri");//throws FileNotFoundException
			//Triple DES encoding
			byte[] privTripleEncoded = tripleEncrypt(pkcs8EncodedKeySpec.getEncoded(), passphrase);
			
			fos.write(privTripleEncoded);//throws IOException
			fos.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * tripleEncrypt - Encrypt message with triple DES method
	 * @param message - string which will be encrypted
	 * @param password - password phrase
	 * @return array of bytes with encrypted data
	 */
	private byte[] tripleEncrypt(byte[] message, String password) {
    	//get md5 hash of password
		MessageDigest md;
		byte[] cipherText = null;
		try {
			md = MessageDigest.getInstance("md5");//throws NoSuchAlgorithmException
	    	byte[] digestOfPassword = md.digest(password.getBytes("utf-8"));//throws UnsupportedEncodingException
	    	//Get copy array of bytes from utf-8 string
	    	byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
	    	//keyBytes = (byte[]) resizeArray(digestOfPassword, 24);
	    	for (int j = 0, k = 16; j < 8;) {
	    		keyBytes[k++] = keyBytes[j++];
	    	}
	    	//Encode message with triple DES
	    	SecretKey key = new SecretKeySpec(keyBytes, "DESede");
	    	IvParameterSpec iv = new IvParameterSpec(new byte[8]);
	    	Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");//throws NoSuchPaddingException
	    	cipher.init(Cipher.ENCRYPT_MODE, key, iv);//throws InvalidKeyException

	    	//byte[] plainTextBytes = message.getBytes("utf-8");
	    	cipherText = cipher.doFinal(message);//throws InvalidKeyException
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

    	return cipherText;
    }
}

