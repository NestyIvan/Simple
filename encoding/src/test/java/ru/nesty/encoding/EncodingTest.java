package ru.nesty.encoding;
import static org.junit.Assert.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;

public class EncodingTest {
	private final static String testWorkingDir = "src\\test\\resources\\ru\\nesty\\encoding";
	
	@BeforeClass
	public static void testBeforeAll(){
		List<File> fl = new ArrayList<File>();
		fl.add(new File(testWorkingDir + "/key.pri"));
		fl.add(new File(testWorkingDir + "/key.pub"));
		
		for(File f : fl){
			if(f.exists()){
				f.delete();
			}
		}
	}
	
	@Test
	public void testCreateKeys(){
		KeyGenerator kg = new KeyGenerator(testWorkingDir, "IfYouHappyAndYouKnowItClapYourHands");
		kg.genKeyPair();
		
		File pkey = new File(testWorkingDir + "/key.pri");
		assertTrue("Private key is not created.", pkey.exists());
		pkey = new File(testWorkingDir + "/key.pub");
		assertTrue("Public key is not created.", pkey.exists());
	}	
}