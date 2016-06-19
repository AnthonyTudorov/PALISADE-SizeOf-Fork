package com.palisade;

import java.util.Arrays;
import com.palisade.PalisadeKeypair;

public class PalisadeCrypto {
	private static final String DEFAULTPARMS = "{ \"parameters\" : \"StehleSteinfeld\", \"plaintextModulus\" : \"2\", \"ring\" :  \"4096\", \"modulus\" : \"17179926529\", \"rootOfUnity\" : \"1874048014\", \"relinWindow\" : \"1\", \"stDev\" : \"4\", \"stDevStSt\" : \"98.4359\" }";

	static {
		System.loadLibrary("PalisadeCryptoWrapper");
	}
	
	private long	object;
	
	public PalisadeCrypto() throws InstantiationException {
		this(DEFAULTPARMS);
	}

	public PalisadeCrypto(String parmset) throws InstantiationException {
		object = openPalisadeCrypto(parmset.getBytes());
		if( object == 0 ) {
			throw new InstantiationException();
		}
	}
		
	private long getObject() {
		return object;
	}
	
	public native PalisadeKeypair generatePalisadeKeyPair(String id);
	public native byte[] generatePalisadeEvalKey(String id, byte[] publicKey, byte[] privateKey);

	public native boolean setPublicKey(byte[] key);
	public native boolean setPrivateKey(byte[] key);
	public native boolean setEvalKey(byte[] key);
	
	public native byte[] encrypt(String id, byte[] cleartext);
	public native byte[] reEncrypt(String id, byte[] ciphertext);
	public native byte[] decrypt(String id, byte[] ciphertext);
	
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

	private native long openPalisadeCrypto(byte[] parmset);
	private native void closePalisadeCrypto();
	
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

		PalisadeKeypair kPublisher = ctx.generatePalisadeKeyPair("pub");
		PalisadeKeypair kSubscriber = ctx.generatePalisadeKeyPair("sub");
		
		System.out.println("Generating Eval Key");

		byte[] evk = ctx.generatePalisadeEvalKey("pubsub", kSubscriber.getPubK(), kPublisher.getPrivK());

		if( evk == null ) {
			System.out.println("no eval key?");
			return;
		}

		ctx.setPublicKey(kPublisher.getPubK());
		ctx.setPrivateKey(kPublisher.getPrivK());
		
		byte[] enc1 = ctx.encrypt("try", cleartext.getBytes("UTF-8"));
		byte[] dec1 = ctx.decrypt("try", enc1);
		System.out.println( new String(dec1) );

		ctx.setPrivateKey(kSubscriber.getPrivK());
		ctx.setEvalKey(evk);

		System.out.println("encrypting");
		byte[] cipher = ctx.encrypt("enc", cleartext.getBytes("UTF-8"));
		if( cipher != null ) {
			if( Arrays.equals(enc1, cipher) ) System.out.println("matches!");
			
			System.out.println("re encrypting");
			byte[] reEnc = ctx.reEncrypt("re", cipher);
			if( reEnc != null ) {
				System.out.println("decrypting");
				byte[] output = ctx.decrypt("de", reEnc);

				if( output != null ) {	
					System.out.println( new String(output) );
				}
			}
		}
		ctx.close();
	}

}
