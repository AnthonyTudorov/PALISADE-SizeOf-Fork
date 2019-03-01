package com.palisade;

/**
 * The class PALISADE
 *
 * This object provides PALISADE services to Java applications
 *
 * NOTES:
 * 1. Operations to generate CryptoContexts and keys are NOT exposed; we assume
 *    that these objects are generated from outside the application and preloaded
 * 2. The PALISADE object can be initialized by loading a serialized context,
 *    OR by preloading a serialized key that contains a context serialization
 * 3. There is intended to be a 1:1 correspondence between this object and
 *    the PALISADE CryptoContext that it represents
 * 4. Objects such as keys and Ciphertexts are maintained in the C++ layer;
 *    these objects are identified by small non-negative integers that are
 *    used as arguments to the crypto methods
 * 5. There needs to be, but is not yet, a mechanism to clean up the
 *    objects at the C++ layer when we're done with them
 */
public class PALISADE {
    static {
        System.loadLibrary("gmp");
        System.loadLibrary("ntl");
        System.loadLibrary("PALISADEcore");
        System.loadLibrary("PALISADEpke");
        System.loadLibrary("PALISADEjni");
    }

    private boolean initialized;

    /**
     * Instantiates a new PALISADE.
     */
    public PALISADE() {
        this.initialized = false;
    }

    /**
     * Initializes PALISADE from a serialized context
     *
     * @param serializedContext the serialized context
     * @return true on success, false on failure
     */
    public boolean InitFromContext(byte[] serializedContext) {
        if( initialized ) {
            // it's an error to initialize an already-initialized ctx
            return false;
        }
        initialized = loadcontext(serializedContext);
        return initialized;
    }

    /**
     * Initializes PALISADE from a serialized public key
     * The serialization must contain a serialized context
     *
     * @param serializedPubKey the serialized pub key
     * @return non-negative int identifying the public key; other values indicate failure
     */
    public int InitFromPubKey(byte[] serializedPubKey) {
        if( initialized ) {
            // it's an error to initialize an already-initialized ctx
            return -1;
        }
        int kID = loadpubkeyctx(serializedPubKey);
        if( kID >= 0 )
            initialized = true;
        return kID;
    }

    /**
     * Initializes PALISADE from a serialized private key
     * The serialization must contain a serialized context
     *
     * @param serializedPrivKey the serialized private key
     * @return non-negative int identifying the private key; other values indicate failure
     */
    public int InitFromPrivKey(byte[] serializedPrivKey) {
        if( initialized ) {
            // it's an error to initialize an already-initialized ctx
            return -1;
        }
        int kID = loadprivkeyctx(serializedPrivKey);
        if( kID >= 0 )
            initialized = true;
        return kID;
    }

    // LATER: InitFromCiphertext?

    /**
     * Install a serialized public key into PALISADE
     *
     * @param serializedPubKey the serialized pub key
     * @return non-negative int identifying the public key; other values indicate failure
     */
    public int InstallPubKey(byte[] serializedPubKey) {
        if( !initialized ) {
            return -1;
        }
        return loadpubkey(serializedPubKey);
    }

    /**
     * Serialize an existing public key
     *
     * @param keyid non negative integer identifying an existing key (installed or created)
     * @return byte array containing the serialization of the key; nil on failure
     */
    public byte[] SerializePubKey(int keyid) {
        if( !initialized ) {
            return null;
        }
        return serpubkey(keyid);
    }

    /**
     * Install a serialized private key into PALISADE
     *
     * @param serializedPrivKey the serialized private key
     * @return non-negative int identifying the private key; other values indicate failure
     */
    public int InstallPrivKey(byte[] serializedPrivKey) {
        if( !initialized ) {
            return -1;
        }
        return loadprivkey(serializedPrivKey);
    }

    /**
     * Serialize an existing private key
     *
     * @param keyid non negative integer identifying an existing key (installed or created)
     * @return byte array containing the serialization of the key; nil on failure
     */
    public byte[] SerializePrivKey(int keyid) {
        if( !initialized ) {
            return null;
        }
        return serprivkey(keyid);
    }

    /**
     * Install a serialized proxy re-encryption key into PALISADE
     *
     * @param serializedPREKey the serialized pre key
     * @return non-negative int identifying the private key; other values indicate failure
     */
    public int InstallPREKey(byte[] serializedPREKey) {
        if( !initialized ) {
            return -1;
        }
        return loadprekey(serializedPREKey);
    }

    /**
     * Serialize an existing proxy re-encryption key
     *
     * @param keyid non negative integer identifying an existing key (installed or created)
     * @return byte array containing the serialization of the key; nil on failure
     */
    public byte[] SerializePREKey(int keyid) {
        if( !initialized ) {
            return null;
        }
        return serprekey(keyid);
    }

    /**
     * Install a serialized ciphertext into PALISADE
     *
     * @param serializedCiphertext the serialized ciphertext
     * @return non-negative int identifying the ciphertext; other values indicate failure
     */
    public int InstallCiphertext(byte[] serializedCiphertext) {
        if( !initialized ) {
            return -1;
        }
        return loadct(serializedCiphertext);
    }

    /**
     * Serialize an existing ciphertext
     *
     * @param ctid non negative integer identifying an existing ciphertext (installed or created)
     * @return byte array containing the serialization of the ciphertext; nil on failure
     */
    public byte[] SerializeCipherext(int ctid) {
        if( !initialized ) {
            return null;
        }
        return serct(ctid);
    }

    // Crypto Operations


    /**
     * Encrypt an array of plaintext bytes into a ciphertext with a public key
     *
     * @param plaintext   array of bytes to encrypt
     * @param publicKeyId non negative integer identifying a public key
     * @return the int
     */
    public int Encrypt(byte[] plaintext, int publicKeyId) {
        if( !initialized ) {
            return -1;
        }
        return encrypt(plaintext, publicKeyId);
    }

    /**
     * Re encrypt a ciphertext into another cyphertext with a PRE key
     *
     * @param ciphertextId non negative integer identifying a ciphertext
     * @param PREkeyId     non negative integer identifying a proxy re-encryption key
     * @return non negative integer identifying a ciphertext; other values indicate failure
     */
    public int ReEncrypt(int ciphertextId, int PREkeyId) {
        if( !initialized ) {
            return -1;
        }
        return reencrypt(ciphertextId, PREkeyId);

    }

    /**
     * Decrypt a ciphertext into an array of plaintext bytes with a private key
     *
     * @param ciphertextId non negative integer identifying a ciphertext
     * @param privateKeyId non negative integer identifying a private key
     * @return new array of bytes with decrypted plaintext; null on failure
     */
    public byte[] Decrypt(int ciphertextId, int privateKeyId) {
        if( !initialized ) {
            return null;
        }
        return decrypt(ciphertextId, privateKeyId);

    }

    // hooks into library

    private native boolean loadcontext(byte[] serializedContext);
    private native int loadpubkeyctx(byte[] serializedPubKey);
    private native int loadprivkeyctx(byte[] serializedPrivKey);
    private native int loadpubkey(byte[] serializedPubKey);
    private native byte[] serpubkey(int keyid);
    private native int loadprivkey(byte[] serializedPrivKey);
    private native byte[] serprivkey(int keyid);
    private native int loadprekey(byte[] serializedPREKey);
    private native byte[] serprekey(int keyid);
    private native int loadct(byte[] serializedCiphertext);
    private native byte[] serct(int ctid);
    private native int encrypt(byte[] plaintext, int publicKeyId);
    private native int reencrypt(int ciphertextId, int PREkeyId);
    private native byte[] decrypt(int ciphertextId, int privateKeyId);
}
