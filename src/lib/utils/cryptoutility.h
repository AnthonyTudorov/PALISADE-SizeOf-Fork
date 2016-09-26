#ifndef LIB_ENCODING_CRYPTOUTILITY
#define LIB_ENCODING_CRYPTOUTILITY

#include <iostream>
#include "../encoding/plaintext.h"
#include "../encoding/byteplaintextencoding.h"
#include "../utils/serializablehelper.h"

namespace lbcrypto {

template<typename Element>
class CryptoUtility {
public:

	static bool ReKeyGen(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPPublicKey<Element> &newPublicKey,
			const LPPrivateKey<Element> &origPrivateKey,
			LPEvalKey<Element> *evalKey)
	{
		if( typeid(Element) == typeid(ILVectorArray2n) ) {
			throw std::logic_error("Sorry, re-encryption keys have not been implemented with Element of ILVectorArray2n");
		}

		return scheme.ReKeyGen(newPublicKey, origPrivateKey, evalKey);
	}

	/**
	 * Perform an encryption of a plaintext
	 * @param scheme - a reference to the encryption scheme in use
	 * @param publicKey - the encryption key in use
	 * @param plaintext - array of bytes to be encrypted
	 * @param ciphertext - resulting vector of ciphertext, one per chunk
	 * @param doPadding - if false, padding is not used; plaintext MUST be an integral multiple of chunksize or an exception is thrown
	 * @return
	 */
	static EncryptResult Encrypt(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPPublicKey<Element>& publicKey,
			const Plaintext& plaintext,
			std::vector<shared_ptr<Ciphertext<Element>>> *cipherResults,
			bool doPadding = true)
	{
		const BigBinaryInteger& ptm = publicKey.GetCryptoParameters().GetPlaintextModulus();
		size_t chunkSize = plaintext.GetChunksize(publicKey.GetCryptoParameters().GetElementParams().GetCyclotomicOrder(), ptm);
		size_t ptSize = plaintext.GetLength();
		size_t rounds = ptSize/chunkSize;

		if( doPadding == false && ptSize%chunkSize != 0 ) {
			throw std::logic_error("Cannot Encrypt without padding with this plaintext size");
		}

		// if there is a partial chunk OR if there isn't but we need to pad
		if( ptSize%chunkSize != 0 || doPadding == true )
			rounds += 1;

		for( int bytes=0, i=0; i < rounds ; bytes += chunkSize,i++ ) {

			Element pt(publicKey.GetCryptoParameters().GetElementParams());
			plaintext.Encode(ptm, &pt, bytes, chunkSize);
			pt.SwitchFormat();

			shared_ptr<Ciphertext<Element>> ciphertext = scheme.Encrypt(publicKey,pt);

			if( !ciphertext ) return EncryptResult();

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
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPPublicKey<Element>& publicKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		bool padded = false;
		BytePlaintextEncoding px;
		const BigBinaryInteger& ptm = publicKey.GetCryptoParameters().GetPlaintextModulus();
		size_t chunkSize = px.GetChunksize(publicKey.GetCryptoParameters().GetElementParams().GetCyclotomicOrder(), ptm);
		char *ptxt = new char[chunkSize];
		size_t totBytes = 0;

		while( instream.good() ) {
			instream.read(ptxt, chunkSize);
			size_t nRead = instream.gcount();

			if( nRead <= 0 && padded )
				break;

			BytePlaintextEncoding px(ptxt, nRead);

			if( nRead < chunkSize ) {
				padded = true;
			}

			Element pt(publicKey.GetCryptoParameters().GetElementParams());
			px.Encode(publicKey.GetCryptoParameters().GetPlaintextModulus(), &pt, 0, chunkSize);
			pt.SwitchFormat();

			Ciphertext<Element> ciphertext;
			EncryptResult res = scheme.Encrypt(publicKey, pt, &ciphertext);
			if( res.isValid == false ) {
				delete ptxt;
				return EncryptResult();
			}

			totBytes += res.numBytesEncrypted;

			Serialized cS;

			if( ciphertext.Serialize(&cS, "ct") ) {
				if( !SerializableHelper::SerializationToStream(cS, outstream) ) {
					delete ptxt;
					return EncryptResult();
				}
			} else {
				delete ptxt;
				return EncryptResult();
			}
		}

		delete ptxt;
		return EncryptResult(totBytes);
	}

	/**
	 * perform a decryption of a vector of ciphertext
	 * @param scheme - a reference to the encryption scheme in use
	 * @param privateKey - reference to the decryption key
	 * @param ciphertext - reference to a vector of ciphertext to be decrypted
	 * @param plaintext - destination for the decrypted ciphertext
	 * @param doPadding - if false, the encryptor did NOT use padding, so do not unpad; default is to use padding
	 * @return
	 */
	static DecryptResult Decrypt(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPPrivateKey<Element>& privateKey,
			const std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext,
			Plaintext *plaintext,
			bool doPadding = true)
	{
		bool dbg_flag = false;
		int lastone = ciphertext.size() - 1;
		for( int ch = 0; ch < ciphertext.size(); ch++ ) {
			DEBUG("ch:" << ch);
			Element decrypted;
			DecryptResult result = scheme.Decrypt(privateKey, ciphertext[ch], &decrypted);
			DEBUG("result valid "<<result.isValid<< " msg length "<<result.messageLength );
			if( result.isValid == false ) return result;

			plaintext->Decode(privateKey.GetCryptoParameters().GetPlaintextModulus(), &decrypted);

			if( ch == lastone && doPadding ) {
				plaintext->Unpad(privateKey.GetCryptoParameters().GetPlaintextModulus());
			}
		}
		DEBUG("decrypting");
		return DecryptResult(plaintext->GetLength());
	}

	/**
	 * read a stream for a sequence of serialized ciphertext; deserialize it, decrypt it, and write it to another stream
	 * @param ctx - a pointer to the crypto context used in this session
	 * @param privateKey - reference to the decryption key
	 * @param instream - input stream with sequence of serialized ciphertexts
	 * @param outstream - output stream for plaintext
	 * @return
	 */
	static DecryptResult Decrypt(
			CryptoContext<Element> *ctx,
			const LPPrivateKey<Element>& privateKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		Serialized serObj;
		size_t tot = 0;

		bool firstTime = true;
		BytePlaintextEncoding pte[2];
		bool whichArray = false;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
//			Ciphertext<Element> ct;
//			if( ct.Deserialize(serObj, ctx) ) {
//				Element decrypted;
//				DecryptResult res = ctx->getAlgorithm()->Decrypt(privateKey, ct, &decrypted);
//				if( !res.isValid )
//					return DecryptResult();
//				tot += res.messageLength;
//
//				pte[whichArray].Decode(privateKey.GetCryptoParameters().GetPlaintextModulus(), &decrypted);
//
//				if( !firstTime ) {
//					outstream << pte[!whichArray];
//					pte[!whichArray].clear();
//				}
//				firstTime = false;
//				whichArray = !whichArray;
//			}
//			else
				return DecryptResult();
		}

		// unpad and write the last one
		pte[!whichArray].Unpad(privateKey.GetCryptoParameters().GetPlaintextModulus());
		outstream << pte[!whichArray];

		return DecryptResult(tot);
	}

	/**
	 * perform re-encryption on a vector of ciphertext
	 * @param scheme - a reference to the encryption scheme in use
	 * @param evalKey - reference to the re-encryption key
	 * @param ciphertext - vector of ciphertext
	 * @param newCiphertext - contains a vector of re-encrypted ciphertext
	 */
	static void ReEncrypt(
			const LPPublicKeyEncryptionScheme<Element>& scheme,
			const LPEvalKey<Element> &evalKey,
			const std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext,
			std::vector<shared_ptr<Ciphertext<Element>>> *newCiphertext)
	{
		for( int i=0; i < ciphertext.size(); i++ ) {
			newCiphertext->push_back( scheme.ReEncrypt(evalKey, *ciphertext[i]) );
		}
	}

	/**
	 * perform re-encryption using streams
	 * @param ctx - a pointer to the crypto context used in this session
	 * @param evalKey - reference to the re-encryption key
	 * @param instream - input stream with sequence of serialized ciphertext
	 * @param outstream - output stream with sequence of serialized re-encrypted ciphertext
	 */
	static void ReEncrypt(
			const CryptoContext<Element> *ctx,
			const LPEvalKey<Element> &evalKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		Serialized serObj;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
//			Ciphertext<Element> ct;
//			if( ct.Deserialize(serObj, ctx) ) {
//				Ciphertext<Element> reCt;
//				ctx->getAlgorithm()->ReEncrypt(evalKey, ct, &reCt);
//
//				Serialized serReObj;
//				if( reCt.Serialize(&serReObj, "re") ) {
//					SerializableHelper::SerializationToStream(serReObj, outstream);
//				}
//				else {
//					return; // error
//				}
//			}
//			else {
				return;
//			}
		}
	}

	//KeySwitch(const LPEvalKeyNTRU<Element> &keySwitchHint,const Ciphertext<Element> &cipherText)
	/**
	* perform KeySwitch on a vector of ciphertext
	* @param scheme - a reference to the encryption scheme in use
	* @param keySwitchHint - reference to KeySwitchHint
	* @param ciphertext - vector of ciphertext
	* @param newCiphertext - contains a vector of KeySwitched ciphertext
	*/
	static void KeySwitch(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		const LPEvalKeyNTRU<Element> &keySwitchHint,
		const vector<shared_ptr<Ciphertext<Element>>>& ciphertext,
		vector<shared_ptr<Ciphertext<Element>>> *newCiphertext)
	{
		for (int i = 0; i < ciphertext.size(); i++) {
			newCiphertext->push_back( scheme.KeySwitch(keySwitchHint, *ciphertext.at(i)) );
		}
	}

	/**
	* perform ModReduce on a vector of ciphertext
	* @param scheme - a reference to the encryption scheme in use
	* @param ciphertext - vector of ciphertext
	*/
	static void ModReduce(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		vector<shared_ptr<Ciphertext<Element>>> *ciphertext)
	{
		for (int i = 0; i < ciphertext->size(); i++) {
			scheme.ModReduce(ciphertext->at(i));
		}
	}

	/**
	* perform RingReduce on a vector of ciphertext
	* @param &scheme - a reference to the encryption scheme in use
	* @param ciphertext - vector of ciphertext
	* @param &keySwitchHint - is the keySwitchHint from original private key to sparse private key
	*/
	//void RingReduce(Ciphertext<Element> *cipherText, const LPEvalKeyNTRU<Element> &keySwitchHint) const
	static void RingReduce(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		vector<shared_ptr<Ciphertext<Element>>> *ciphertext,
		const LPEvalKeyNTRU<Element> &keySwitchHint)

	{
		for (int i = 0; i < ciphertext->size(); i++) {
			scheme.RingReduce(&(*ciphertext->at(i)), keySwitchHint);
		}
	}

	/**
	* perform RingReduce on a vector of ciphertext
	* @param &scheme - a reference to the encryption scheme in use
	* @param ciphertext1 - first cipher text
	* @param ciphertext2 - second cipher text
	* @param &quadKeySwitchHint - is the quadratic key switch hint from original private key to the quadratic key
	* @param ciphertextResult - resulting ciphertext
	*/
	static void ComposedEvalMult(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		const vector<Ciphertext<Element>> &ciphertext1,
		const vector<Ciphertext<Element>> &ciphertext2,
		const LPEvalKeyNTRU<Element> &quadKeySwitchHint, 
		vector<shared_ptr<Ciphertext<Element>>> *ciphertextResult
		)
	{
		if (ciphertext1.size() != ciphertext2.size()) {
			throw std::logic_error("Cannot have ciphertext of different length");
		}
		for (int i = 0; i < ciphertext1.size(); i++) {
			scheme.ComposedEvalMult(ciphertext1.at(i), ciphertext2.at(i), quadKeySwitchHint, ciphertextResult->at(i));
		}
	}

};

}

#endif
