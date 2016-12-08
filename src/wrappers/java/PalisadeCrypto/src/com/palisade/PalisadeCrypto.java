package com.palisade;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import com.palisade.PalisadeKeypair;

public class PalisadeCrypto {
	private static final String DEFAULTPARMS = "{ \"parameters\" : \"StehleSteinfeld\", \"plaintextModulus\" : \"256\", " +
			"\"ring\" : \"8192\", \"modulus\" : \"75557863725914323468289\", \"rootOfUnity\" : \"36933905409054618621009\", " +
			"\"relinWindow\" : \"16\", \"stDev\" : \"4\", \"stDevStSt\" : \"41411.5\"  }";
	static {
		System.loadLibrary("PalisadeCryptoWrapper");
	}
	
	private long	object;
	
	/**
	 * Constructs a PalisadeCrypto with default parameters
	 * @throws InstantiationException
	 */
	public PalisadeCrypto() throws InstantiationException {
		this(DEFAULTPARMS);
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
	 * 
	 * @param id - string to identify the keypair
	 * @return a PalisadeKeypair with a public and private key JSON array
	 */
	public native PalisadeKeypair generatePalisadeKeyPair(String id);
	
	/**
	 * 
	 * @param id - string to identify the key
	 * @param publicKey - subscriber's public key
	 * @param privateKey - publisher's private key
	 * @return - serialized JSON array containing the evaluation key
	 */
	public native byte[] generatePalisadeEvalKey(String id, byte[] publicKey, byte[] privateKey);

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
	 * @param id - identifies the encryption
	 * @param cleartext - the text to be encrypted
	 * @return - JSON serialization of the ciphertext
	 */
	public native byte[] encrypt(String id, byte[] cleartext);
	
	/**
	 * Re-Encrypt using the key set in #setEvalKey
	 * @param id - identifies the encryption
	 * @param ciphertext - the JSON serialization of the payload to be re-encrypted
	 * @return - JSON serialization of the ciphertext
	 */
	public native byte[] reEncrypt(String id, byte[] ciphertext);
	
	/**
	 * Decrypt using the key set in #setPrivateKey
	 * @param id - identifies the encryption
	 * @param ciphertext - the JSON serialization of the payload to be decrypted
	 * @return - cleartext byte array
	 */
	public native byte[] decrypt(String id, byte[] ciphertext);
	
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
		
		System.out.println("Testing stream stuff...");
		
		FileInputStream fr;
		try {
			fr = new FileInputStream(args[0]);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return;
		}
		String message = "HI:::";
		try {
			ctx.writeBytes(message.getBytes(), fr, System.err);
		} catch( Exception e ) {
			System.out.println("Exception in write");
			e.printStackTrace();
		}

		System.err.flush();
		System.out.println("...stream test done");
		
		System.out.println("Generating some key pairs");

		PalisadeKeypair kPublisher = ctx.generatePalisadeKeyPair("pub");
		if( kPublisher == null ) {
			System.out.println("could not create a publisher keypair: " + new String(ctx.getPalisadeErrorDescription()));
			return;
		}
		
		PalisadeKeypair kSubscriber = ctx.generatePalisadeKeyPair("sub");
		if( kSubscriber == null ) {
			System.out.println("could not create a subscriber keypair: " + new String(ctx.getPalisadeErrorDescription()));
			return;
		}
		
		System.out.println("Generating Eval Key");

		byte[] evk = ctx.generatePalisadeEvalKey("pubsub", kSubscriber.getPubK(), kPublisher.getPrivK());

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
		byte[] enc1 = ctx.encrypt("try", cleartext.getBytes("UTF-8"));
		
		if( enc1 == null ) {
			System.out.println("Failed to encrypt: " + new String(ctx.getPalisadeErrorDescription()));
			return;
		}
		
		System.out.println("Decrypting...");
		byte[] dec1 = ctx.decrypt("try", enc1);
		
		if( dec1 == null ) {
			System.out.println("Failed to decrypt");
			return;
		}
		System.out.println( new String(dec1) );

		ctx.setPrivateKey(kSubscriber.getPrivK());
		ctx.setEvalKey(evk);

		System.out.println("Encrypting");
		byte[] cipher = ctx.encrypt("enc", cleartext.getBytes("UTF-8"));
		if( cipher != null ) {
			if( Arrays.equals(enc1, cipher) ) System.out.println("matches!");
			
			System.out.println("Re encrypting");
			byte[] reEnc = ctx.reEncrypt("re", cipher);
			if( reEnc != null ) {
				System.out.println("Decrypting");
				byte[] output = ctx.decrypt("de", reEnc);

				if( output != null ) {	
					System.out.println( new String(output) );
				}
			}
		}
		ctx.close();
	}

}
