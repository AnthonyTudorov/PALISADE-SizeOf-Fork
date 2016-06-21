package com.palisade;

public class PalisadeKeypair {
	private byte[]		pubK;
	private byte[]		secretK;
	
	public PalisadeKeypair(byte[] pubK, byte[] secretK) {
		this.pubK = pubK;
		this.secretK = secretK;
	}
	
	public byte[] getPubK() { return pubK; }
	public byte[] getPrivK() { return secretK; }

	public String toString() {
		return  "Pub: " + new String( pubK ) + "\n" +
			"Pri:" + new String( secretK );
	}
}
