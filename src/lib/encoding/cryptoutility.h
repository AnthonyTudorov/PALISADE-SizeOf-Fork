#ifndef LIB_ENCODING_CRYPTOUTILITY
#define LIB_ENCODING_CRYPTOUTILITY

#include <iostream>
#include "byteencoding.h"

namespace lbcrypto {

template<typename Element>
class CryptoUtility {
public:

	/**
	 * Perform an encryption of a plaintext
	 * @param scheme - a reference to the encryption scheme in use
	 * @param publicKey - the encryption key in use
	 * @param plaintext - array of bytes to be encrypted
	 * @param ciphertext - resulting vector of ciphertext, one per chunk
	 * @return
	 */
	static EncryptResult Encrypt(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPPublicKey<Element>& publicKey,
			const ByteArray& plaintext,
			vector<Ciphertext<Element>> *cipherResults)
	{
		size_t chunkSize = scheme.getChunkSize();
		size_t ptSize = plaintext.size();

		for( int bytes=0; bytes < ptSize; bytes += chunkSize ) {

			ByteArrayPlaintextEncoding px(plaintext, bytes, chunkSize);
			px.Pad<ZeroPad>(chunkSize);

			Element pt(publicKey.GetCryptoParameters().GetElementParams());
			px.Encode(publicKey.GetCryptoParameters().GetPlaintextModulus(), &pt);
			pt.SwitchFormat();

			Ciphertext<Element> ciphertext;
			EncryptResult result = scheme.Encrypt(publicKey,pt,&ciphertext);

			if( result.isValid == false ) return result;

			cipherResults->push_back(ciphertext);
		}

		return EncryptResult(ptSize);
	}

	static EncryptResult Encrypt(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPPublicKey<Element>& publicKey,
			istream& instream,
			ostream& ostream)
	{
		size_t chunkSize = scheme.getChunkSize();
		//size_t ptSize = plaintext.size();

		return EncryptResult();
	}


	static DecryptResult Decrypt(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPPrivateKey<Element>& privateKey,
			const vector<Ciphertext<Element>>& ciphertext,
			ByteArray *plaintext)
	{
		for( int ch = 0; ch < ciphertext.size(); ch++ ) {
			Element decrypted;
			DecryptResult result = scheme.Decrypt(privateKey, ciphertext[ch], &decrypted);

			if( result.isValid == false ) return result;

			ByteArrayPlaintextEncoding pte;

			pte.Decode(privateKey.GetCryptoParameters().GetPlaintextModulus(), decrypted);
			pte.Unpad<ZeroPad>();

			plaintext->insert( plaintext->end(), pte.GetData().begin(), pte.GetData().end() );
		}

		return DecryptResult(plaintext->size());
	}

	static void ReEncrypt(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		const LPEvalKey<Element> &evalKey,
		const vector<Ciphertext<Element>>& ciphertext,
		vector<Ciphertext<Element>> *newCiphertext)
		{
			for( int i=0; i < ciphertext.size(); i++ ) {
				Ciphertext<Element> nCipher;
				scheme.ReEncrypt(evalKey, ciphertext[i], &nCipher);
				newCiphertext->push_back(nCipher);
			}
		}

};

}

#endif
