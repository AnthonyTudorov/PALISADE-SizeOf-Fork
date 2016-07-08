#ifndef LIB_ENCODING_CRYPTOUTILITY
#define LIB_ENCODING_CRYPTOUTILITY

#include <iostream>
#include "byteencoding.h"
#include "../utils/serializablehelper.h"

namespace lbcrypto {

template<typename Element>
class CryptoUtility {
public:

	static bool KeyGen(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			LPPublicKey<Element> *publicKey,
			LPPrivateKey<Element> *privateKey)
	{
		return scheme.KeyGen(publicKey, privateKey);
	}

	static bool EvalKeyGen(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPPublicKey<Element> &newPublicKey,
					const LPPrivateKey<Element> &origPrivateKey,
					LPEvalKey<Element> *evalKey)
	{
		return scheme.EvalKeyGen(newPublicKey, origPrivateKey, evalKey);
	}

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

	/**
	 * Perform an encryption by reading plaintext from a stream, serializing each piece of ciphertext,
	 * and writing the serializations to an output stream
	 * @param scheme - a reference to the encryption scheme in use
	 * @param publicKey - the encryption key in use
	 * @param instream - where to read the input from
	 * @param ostream - where to write the serialization to
	 * @return
	 */
	static EncryptResult Encrypt(
			const CryptoContext<Element> *ctx,
			const LPPublicKey<Element>& publicKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		size_t chunkSize = ctx->getAlgorithm()->getChunkSize();
		char *ptxt = new char[chunkSize];
		size_t totBytes = 0;

		while( instream.good() ) {
			instream.read(ptxt, chunkSize);
			size_t nRead = instream.gcount();

			if( nRead <= 0 )
				break;

			ByteArray pt(ptxt, nRead);
			vector<Ciphertext<Element>> cipherResults;

			EncryptResult res = Encrypt(*ctx->getAlgorithm(), publicKey, pt, &cipherResults);
			if( res.isValid == false ) {
				delete ptxt;
				return res;
			}

			totBytes += res.numBytesEncrypted;

			for( int i=0; i<cipherResults.size(); i++ ) {
				Ciphertext<Element> oneCt(cipherResults.at(i));

				Serialized cS;

				if( oneCt.Serialize(&cS, "ct") ) {
					if( !SerializableHelper::SerializationToStream(cS, outstream) ) {
						delete ptxt;
						return EncryptResult();
					}
				} else {
					delete ptxt;
					return EncryptResult();
				}
			}

			cipherResults.clear();
		}

		delete ptxt;
		return EncryptResult(totBytes);
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

	static DecryptResult Decrypt(
			const CryptoContext<Element> *ctx,
			const LPPrivateKey<Element>& privateKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		Serialized serObj;
		size_t tot = 0;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			Ciphertext<Element> ct;
			if( ct.Deserialize(serObj, ctx) ) {
				Element decrypted;
				DecryptResult res = ctx->getAlgorithm()->Decrypt(privateKey, ct, &decrypted);
				if( !res.isValid )
					return DecryptResult();
				tot += res.messageLength;

				ByteArrayPlaintextEncoding pte;
				pte.Decode(privateKey.GetCryptoParameters().GetPlaintextModulus(), decrypted);
				pte.Unpad<ZeroPad>();

				outstream << pte.GetData();
			}
			else
				return DecryptResult();
		}

		return DecryptResult(tot);
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

	static void ReEncrypt(
			const CryptoContext<Element> *ctx,
			const LPEvalKey<Element> &evalKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		Serialized serObj;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			Ciphertext<Element> ct;
			if( ct.Deserialize(serObj, ctx) ) {
				Ciphertext<Element> reCt;
				ctx->getAlgorithm()->ReEncrypt(evalKey, ct, &reCt);

				Serialized serReObj;
				if( reCt.Serialize(&serReObj, "re") ) {
					SerializableHelper::SerializationToStream(serReObj, outstream);
				}
				else {
					return; // error
				}
			}
			else {
				return;
			}
		}
	}


};

}

#endif
