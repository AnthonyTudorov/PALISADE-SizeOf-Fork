package com.palisade;

public class PalisadeKeypair {
	private byte[]		pubK;
	private byte[]		secretK;
	
	/**
	 * Create a new Palisade Keypair
	 * NOTE the library uses this to save the results of keypair creation
	 * @param pubK - public portion of the key
	 * @param secretK - secret portion of the key
	 */
	public PalisadeKeypair(byte[] pubK, byte[] secretK) {
		this.pubK = pubK;
		this.secretK = secretK;
	}
	
	/**
	 * 
	 * @return the public key
	 */
	public byte[] getPubK() { return pubK; }
	
	/**
	 * 
	 * @return the secret key
	 */
	public byte[] getPrivK() { return secretK; }

	public String toString() {
		return  "Pub: " + new String( pubK ) + "\n" +
			"Pri:" + new String( secretK );
	}
}
