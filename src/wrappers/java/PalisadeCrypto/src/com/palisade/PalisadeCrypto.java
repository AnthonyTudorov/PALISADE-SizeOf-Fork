package com.palisade;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import com.palisade.PalisadeKeypair;

public class PalisadeCrypto {
	private static final String PARMSET = "StSt6";
	static {
		System.loadLibrary("PalisadeCryptoWrapper");
	}
	
	private long	object;
	
	/**
	 * Constructs a PalisadeCrypto with default parameters
	 * @throws InstantiationException
	 */
	public PalisadeCrypto() throws InstantiationException {
		this(PARMSET);
	}

	/**
	 * 
	 * @param parmset - JSON string of parameters for creating a PalisadeCrypto
	 * @throws InstantiationException
	 */
	public PalisadeCrypto(String parmset) throws InstantiationException {
		object = openPalisadeCrypto(parmset.getBytes());
		if( object == 0 ) {
			throw new InstantiationException();
		}
	}
		
	private long getObject() {
		return object;
	}
	
	/**
	 * generatePalisadeKeypair
	 * @return a PalisadeKeypair with a public and private key JSON array
	 */
	public native PalisadeKeypair generatePalisadeKeyPair();
	
	/**
	 * 
	 * @param publicKey - subscriber's public key
	 * @param privateKey - publisher's private key
	 * @return - serialized JSON array containing the evaluation key
	 */
	public native byte[] generatePalisadeEvalKey(byte[] publicKey, byte[] privateKey);

	/**
	 * Sets the key to be used for Encryption by deserializing the given key bytes
	 * @param key - serialized public key
	 * @return true on success
	 */
	public native boolean setPublicKey(byte[] key);
	
	/**
	 * Sets the key to be used for Decryption by deserializing the given key bytes
	 * @param key - serialized private key
	 * @return
	 */
	public native boolean setPrivateKey(byte[] key);
	
	/**
	 * Sets the key to be used for Re-encryption by deserializing the given key bytes
	 * @param key
	 * @return
	 */
	public native boolean setEvalKey(byte[] key);
	
	/**
	 * Encrypt using the key set in #setPublicKey
	 * @param cleartext - the text to be encrypted
	 * @return - JSON serialization of the ciphertext
	 */
	public native byte[] encrypt(byte[] cleartext);
	
	/**
	 * Re-Encrypt using the key set in #setEvalKey
	 * @param ciphertext - the JSON serialization of the payload to be re-encrypted
	 * @return - JSON serialization of the ciphertext
	 */
	public native byte[] reEncrypt(byte[] ciphertext);
	
	/**
	 * Decrypt using the key set in #setPrivateKey
	 * @param ciphertext - the JSON serialization of the payload to be decrypted
	 * @return - cleartext byte array
	 */
	public native byte[] decrypt(byte[] ciphertext);
	
	/**
	 * Finish with this PalisadeCrypto instance
	 */
	public void close() {
		closePalisadeCrypto();
		object = 0;
	}
	
	protected void finalize() throws Throwable {
		if( object != 0 ) {
			closePalisadeCrypto();
			object = 0;
		}
		
		super.finalize();
	}

	/**
	 * Creates a new object for this PalisadeCrypto in the JNI layer
	 * @param parmset - JSON representation of parameters
	 * @return - reference to the JNI object
	 */
	private native long openPalisadeCrypto(byte[] parmset);
	
	/**
	 * Close the JNI layer for this object
	 */
	private native void closePalisadeCrypto();
	
	public native byte[] getPalisadeErrorDescription();
	
	// demo test program
	public static void main(String args[]) throws java.io.UnsupportedEncodingException {

		String cleartext = "Baseball breaks your heart. It is designed to break your heart. The game begins in the spring, when everything else begins again, and it blossoms in the summer, filling the afternoons and evenings, and then as soon as the chill rains come, it stops and leaves you to face the fall all alone. You count on it, rely on it to buffer the passage of time, to keep the memory of sunshine and high skies alive, and then just when the days are all twilight, when you need it most, it stops.";

		System.out.println("Java Palisade Wrapper Test");
		PalisadeCrypto ctx;
		try {
			ctx = new PalisadeCrypto();
		} catch( InstantiationException e ) {
			System.err.println("Could not create a crypto context for your parm set");
			return;
		}
		
		System.out.println("Generating some key pairs");

		PalisadeKeypair kPublisher = ctx.generatePalisadeKeyPair();
		if( kPublisher == null ) {
			System.out.println("could not create a publisher keypair: " + new String(ctx.getPalisadeErrorDescription()));
			return;
		}
		
		PalisadeKeypair kSubscriber = ctx.generatePalisadeKeyPair();
		if( kSubscriber == null ) {
			System.out.println("could not create a subscriber keypair: " + new String(ctx.getPalisadeErrorDescription()));
			return;
		}
		
		System.out.println("Generating Eval Key");

		byte[] evk = ctx.generatePalisadeEvalKey(kSubscriber.getPubK(), kPublisher.getPrivK());

		if( evk == null ) {
			System.out.println("could not create an eval key: " + new String(ctx.getPalisadeErrorDescription()));
			return;
		}

		System.out.println("Setting keys");
		if( !ctx.setPublicKey(kPublisher.getPubK()) ) {
			System.out.println("Failed to set public key");
			return;
		}
		if( !ctx.setPrivateKey(kPublisher.getPrivK()) ) {
			System.out.println("Failed to set private key");
			return;
		}
		
		System.out.println("Encrypting...");
		byte[] enc1 = ctx.encrypt(cleartext.getBytes("UTF-8"));
		
		if( enc1 == null ) {
			System.out.println("Failed to encrypt: " + new String(ctx.getPalisadeErrorDescription()));
			return;
		}
				
		System.out.println("Decrypting...");
		byte[] dec1 = ctx.decrypt(enc1);
		
		if( dec1 == null ) {
			System.out.println("Failed to decrypt" + new String(ctx.getPalisadeErrorDescription()));
			return;
		}
		String decrypted = new String(dec1, "UTF-8");
		
		if( cleartext.compareTo(decrypted) != 0 ) {
			System.out.println("Mismatch on decrypted payload");
			System.out.println( decrypted );
		}
		else
			System.out.println("Matched!");
		
		ctx.setPrivateKey(kSubscriber.getPrivK());
		ctx.setEvalKey(evk);

		System.out.println("Re-Encryption Testing...");
		
		System.out.println("Encrypting...");
		byte[] cipher = ctx.encrypt(cleartext.getBytes("UTF-8"));
		if( cipher != null ) {
			
			System.out.println("Re encrypting...");
			byte[] reEnc = ctx.reEncrypt(cipher);
			if( reEnc != null ) {
				System.out.println("Decrypting...");
				byte[] output = ctx.decrypt(reEnc);

				if( output != null ) {
					String newDe = new String(output, "UTF-8");
					if( cleartext.compareTo(newDe) != 0 ) {
						System.out.println("Mismatch on decrypted payload");
						System.out.println( newDe );
					}
					else
						System.out.println("Matched!");
				}
			}
		}
		ctx.close();
	}

}
