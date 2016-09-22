/**
* @file
* @author	TPOC:
				Dr. Kurt Rohloff <rohloff@njit.edu>,
			Programmers:
				Jerry Ryan <gwryan@njit.edu>

* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
* OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* @section DESCRIPTION
*
* This file defines the Crypto Context: all the pieces needed to initialize and use the palisade library
*/

#ifndef SRC_DEMO_PRE_CRYPTOCONTEXT_H_
#define SRC_DEMO_PRE_CRYPTOCONTEXT_H_

#include "../palisade.h"
#include "../encoding/plaintext.h"
#include "../encoding/byteplaintextencoding.h"
#include "../utils/cryptocontexthelper.h"

namespace lbcrypto {

//FIXME: comments for doxygen are wrong

/**
 * @brief CryptoContextImpl Class.
 *
 * This class implements a container for the full Crypto Context.
 * Every object in Palisade is created within a context and maintains a shared pointer to its context
 */

template <class Element>
class CryptoContextFactory;

template <class Element>
class CryptoContextImpl : public Serializable {

	friend class CryptoContextFactory<Element>;
	friend class CryptoContext<Element>;

private:
	/* these three parameters get initialized when an instance is constructed; they are used by the context */
	DiscreteGaussianGenerator	dgg;
	DiscreteGaussianGenerator	dggStSt;	// unused unless we use StSt scheme

	shared_ptr<LPCryptoParameters<Element>>	params;	/*!< crypto parameters used for this context */
	LPPublicKeyEncryptionScheme<Element>	*scheme;	/*!< algorithm used; points to keygen and encrypt/decrypt methods */

	CryptoContextImpl() : scheme(0) {}
	CryptoContextImpl(shared_ptr<LPCryptoParameters<Element>> cp) : params(cp), scheme(0) {}

public:
	~CryptoContextImpl() {
		if( scheme ) delete scheme;
	}

	DiscreteGaussianGenerator& GetGenerator() { return dgg; }

	/**
	 *
	 * @return crypto parameters
	 */
	const shared_ptr<LPCryptoParameters<Element>> getCryptoParams() const { return params; }

	/**
	 *
	 * @return crypto algorithm
	 */
	LPPublicKeyEncryptionScheme<Element>* getScheme() const { return scheme; }

	bool Serialize(Serialized* serObj, const std::string fileFlag = "") const { return false; }

	bool SetIdFlag(Serialized* serObj, const std::string flag) const { return true; }

	/**
	* Populate the object from the deserialization of the Serialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	bool Deserialize(const Serialized& serObj) { return false; }
};

/**
 * @brief CryptoContext
 *
 * CryptoContext contains a shared pointer to the implementation of a Crypto Context and
 * wrappers around all of the functionality provided by a context
 *
 * Guards are implemented to ensure that only objects created in/by the context will be used with it
 */
template <class Element>
class CryptoContext {
public:
	shared_ptr<CryptoContextImpl<Element>>	ctx;

	CryptoContext(CryptoContextImpl<Element> *e) {
		ctx = std::make_shared<CryptoContextImpl<Element>>(e);
	}

	operator bool() const { return bool(ctx); }

	void Enable(PKESchemeFeature feature) { ctx->getScheme()->Enable(feature); }

	const LPPublicKeyEncryptionScheme<Element> &GetEncryptionAlgorithm() const { return *ctx->getScheme(); }

	const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return ctx->getCryptoParams(); }

	DiscreteGaussianGenerator& GetGenerator() { return ctx->GetGenerator(); }

	const shared_ptr<ILParams> GetElementParams() {
		return std::static_pointer_cast<ILParams>(ctx->getCryptoParams()->GetElementParams());
	}

	friend bool operator==(const CryptoContext<Element>& a, const CryptoContext<Element>& b) { return a.ctx == b.ctx; }
	friend bool operator!=(const CryptoContext<Element>& a, const CryptoContext<Element>& b) { return a.ctx != b.ctx; }

	LPKeyPair<Element> KeyGen() const {
		return GetEncryptionAlgorithm().KeyGen(*this);
	}

	LPKeyPair<Element> SparseKeyGen() const {
		return GetEncryptionAlgorithm().SparseKeyGen(*this);
	}

	shared_ptr<LPEvalKey<Element>> ReKeyGen(
			const shared_ptr<LPPublicKey<Element>> newPublicKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {

		if( newPublicKey->GetCryptoContext() != *this || origPrivateKey->GetCryptoContext() != *this )
			throw std::logic_error("Keys passed to ReKeyGen were not generated with this crypto context");

		if( typeid(Element) == typeid(ILVectorArray2n) )
			throw std::logic_error("Sorry, re-encryption keys have not been implemented with Element of ILVectorArray2n");

		return GetEncryptionAlgorithm().ReKeyGen(newPublicKey, origPrivateKey);
	}

	shared_ptr<LPEvalKeyNTRU<Element>> EvalMultKeyGen(
			const shared_ptr<LPPrivateKey<Element>> k1,
			const shared_ptr<LPPrivateKey<Element>> k2) const {

		if( k1->GetCryptoContext() != *this || k2->GetCryptoContext() != *this )
			throw std::logic_error("Keys passed to EvalMultKeyGen were not generated with this crypto context");

		return GetEncryptionAlgorithm().EvalMultKeyGen(k1, k2);
	}


	shared_ptr<LPEvalKeyNTRU<Element>> QuadraticEvalMultKeyGen(
			const shared_ptr<LPPrivateKey<Element>> k1,
			const shared_ptr<LPPrivateKey<Element>> k2) const {

		if( k1->GetCryptoContext() != *this || k2->GetCryptoContext() != *this )
			throw std::logic_error("Keys passed to QuadraticEvalMultKeyGen were not generated with this crypto context");

		return GetEncryptionAlgorithm().QuadraticEvalMultKeyGen(k1, k2);
	}

	std::vector<shared_ptr<Ciphertext<Element>>> Encrypt(
			const shared_ptr<LPPublicKey<Element>> publicKey,
			const Plaintext& plaintext,
			bool doPadding = true)
	{
		std::vector<shared_ptr<Ciphertext<Element>>> cipherResults;

		if( publicKey->GetCryptoContext() != *this )
			throw std::logic_error("key passed to Encrypt was not generated with this crypto context");

		const BigBinaryInteger& ptm = publicKey->GetCryptoParameters()->GetPlaintextModulus();
		size_t chunkSize = plaintext.GetChunksize(publicKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(), ptm);
		size_t ptSize = plaintext.GetLength();
		size_t rounds = ptSize/chunkSize;

		if( doPadding == false && ptSize%chunkSize != 0 ) {
				//&& typeid(plaintext) == typeid(BytePlaintextEncoding)) {
			throw std::logic_error("Cannot Encrypt without padding with chunksize " + std::to_string(chunkSize) + " and plaintext size " + std::to_string(ptSize));
		}

		// if there is a partial chunk OR if there isn't but we need to pad
		if( ptSize%chunkSize != 0 || doPadding == true )
			rounds += 1;

		for( int bytes=0, i=0; i < rounds ; bytes += chunkSize,i++ ) {

			Element pt(publicKey->GetCryptoParameters()->GetElementParams());
			plaintext.Encode(ptm, &pt, bytes, chunkSize);

			shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm().Encrypt(publicKey,pt);

			if( !ciphertext ) {
				cipherResults.clear();
				break;
			}

			cipherResults.push_back(ciphertext);

		}

		return cipherResults;
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
	void EncryptStream(
			const shared_ptr<LPPublicKey<Element>> publicKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		bool padded = false;
		BytePlaintextEncoding px;
		const BigBinaryInteger& ptm = publicKey->GetCryptoContext().GetCryptoParameters()->GetPlaintextModulus();
		size_t chunkSize = px.GetChunksize(publicKey->GetCryptoContext().GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(), ptm);
		char *ptxt = new char[chunkSize];

		while( instream.good() ) {
			instream.read(ptxt, chunkSize);
			size_t nRead = instream.gcount();

			if( nRead <= 0 && padded )
				break;

			BytePlaintextEncoding px(ptxt, nRead);

			if( nRead < chunkSize ) {
				padded = true;
			}

			Element pt(publicKey->GetCryptoParameters()->GetElementParams());
			px.Encode(publicKey->GetCryptoParameters()->GetPlaintextModulus(), &pt, 0, chunkSize);

			shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm().Encrypt(publicKey, pt);
			if( !ciphertext ) {
				delete ptxt;
				return;
			}

			Serialized cS;

			if( ciphertext->Serialize(&cS, "ct") ) {
				if( !SerializableHelper::SerializationToStream(cS, outstream) ) {
					delete ptxt;
					return;
				}
			} else {
				delete ptxt;
				return;
			}
		}

		delete ptxt;
		return;
	}

	DecryptResult Decrypt(
			const shared_ptr<LPPrivateKey<Element>> privateKey,
			const std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext,
			Plaintext *plaintext,
			bool doPadding = true)
	{
		// edge case
		if( ciphertext.size() == 0 )
			return DecryptResult();

		if( privateKey->GetCryptoContext() != *this || ciphertext.at(0)->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to Decrypt was not generated with this crypto context");

		int lastone = ciphertext.size() - 1;
		for( int ch = 0; ch < ciphertext.size(); ch++ ) {
			Element decrypted;
			DecryptResult result = GetEncryptionAlgorithm().Decrypt(privateKey, ciphertext[ch], &decrypted);

			if( result.isValid == false ) return result;

			plaintext->Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decrypted);
			if( ch == lastone && doPadding ) {
				plaintext->Unpad(privateKey->GetCryptoParameters()->GetPlaintextModulus());
			}
		}

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
	void DecryptStream(
			const shared_ptr<LPPrivateKey<Element>> privateKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		Serialized serObj;
		size_t tot = 0;

		bool firstTime = true;
		BytePlaintextEncoding pte[2];
		bool whichArray = false;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			shared_ptr<Ciphertext<Element>> ct;
			if( ct = deserializeCiphertext(serObj) ) {
				Element decrypted;
				DecryptResult res = GetEncryptionAlgorithm().Decrypt(privateKey, ct, &decrypted);
				if( !res.isValid )
					return;
				tot += res.messageLength;

				pte[whichArray].Decode(privateKey->GetCryptoParameters()->GetPlaintextModulus(), &decrypted);

				if( !firstTime ) {
					outstream << pte[!whichArray];
					pte[!whichArray].clear();
				}
				firstTime = false;
				whichArray = !whichArray;
			}
			else
				return;
		}

		// unpad and write the last one
		pte[!whichArray].Unpad(privateKey->GetCryptoParameters()->GetPlaintextModulus());
		outstream << pte[!whichArray];

		return;
	}

	std::vector<shared_ptr<Ciphertext<Element>>> ReEncrypt(
			shared_ptr<LPEvalKey<Element>> evalKey,
			std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext)
	{
		if( evalKey->GetCryptoContext() != *this || ciphertext.at(0)->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to ReEncrypt was not generated with this crypto context");

		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext;
		for( int i=0; i < ciphertext.size(); i++ ) {
			newCiphertext.push_back( GetEncryptionAlgorithm().ReEncrypt(evalKey, ciphertext[i]) );
		}

		return newCiphertext;
	}

	/**
	 * perform re-encryption using streams
	 * @param ctx - a pointer to the crypto context used in this session
	 * @param evalKey - reference to the re-encryption key
	 * @param instream - input stream with sequence of serialized ciphertext
	 * @param outstream - output stream with sequence of serialized re-encrypted ciphertext
	 */
	void ReEncryptStream(
			const shared_ptr<LPEvalKey<Element>> evalKey,
			std::istream& instream,
			std::ostream& outstream)
	{
		Serialized serObj;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			shared_ptr<Ciphertext<Element>> ct;
			ct = deserializeCiphertext(serObj);
			if( ct ) {
				std::vector<shared_ptr<Ciphertext<Element>>> allCt;
				allCt.push_back(ct);
				std::vector<shared_ptr<Ciphertext<Element>>> reCt = ReEncrypt(evalKey, allCt);

				Serialized serReObj;
				if( reCt[0]->Serialize(&serReObj, "re") ) {
					SerializableHelper::SerializationToStream(serReObj, outstream);
				}
				else {
					return; // error
				}
				allCt.clear();
			}
			else {
				return;
			}
		}
	}

	shared_ptr<Ciphertext<Element>>
	EvalAdd(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2)
	{
		if( ct1->GetCryptoContext() != *this || ct2->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to EvalAdd was not generated with this crypto context");

		return GetEncryptionAlgorithm().EvalAdd(ct1, ct2);
	}

	shared_ptr<Ciphertext<Element>>
	EvalMult(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2)
	{
		if( ct1->GetCryptoContext() != *this || ct2->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to EvalMult was not generated with this crypto context");

		return GetEncryptionAlgorithm().EvalMult(ct1, ct2);
	}

	/**
	* perform KeySwitch on a vector of ciphertext
	* @param scheme - a reference to the encryption scheme in use
	* @param keySwitchHint - reference to KeySwitchHint
	* @param ciphertext - vector of ciphertext
	*/
	std::vector<shared_ptr<Ciphertext<Element>>> KeySwitch(
		const shared_ptr<LPEvalKey<Element>> keySwitchHint,
		const std::vector<shared_ptr<Ciphertext<Element>>> ciphertext)
	{
		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext;

		if( keySwitchHint->GetCryptoContext() != *this )
			throw std::logic_error("Key passed to KeySwitch was not generated with this crypto context");

		for (int i = 0; i < ciphertext.size(); i++) {
			if( ciphertext.at(i)->GetCryptoContext() != *this )
				throw std::logic_error("Information passed to KeySwitch was not generated with this crypto context");

			newCiphertext.push_back( GetEncryptionAlgorithm().KeySwitch(keySwitchHint, ciphertext[i]) );
		}

		return newCiphertext;
	}

	/**
	* perform ModReduce on a vector of ciphertext
	* @param scheme - a reference to the encryption scheme in use
	* @param ciphertext - vector of ciphertext
	*/
	std::vector<shared_ptr<Ciphertext<Element>>> ModReduce(
		vector<shared_ptr<Ciphertext<Element>>> ciphertext)
	{
		for (int i = 0; i < ciphertext.size(); i++) {
			if( ciphertext.at(i)->GetCryptoContext() != *this )
				throw std::logic_error("Information passed to ModReduce was not generated with this crypto context");

			GetEncryptionAlgorithm().ModReduce(ciphertext[i]);
		}

		return ciphertext;
	}

	shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
			const shared_ptr<LPEvalKeyNTRU<Element>> linearKeySwitchHint) const {

		if( cipherText1->GetCryptoContext() != *this || linearKeySwitchHint->GetCryptoContext() != *this) {
			throw std::logic_error("Information passed to LevelReduce was not generated with this crypto context");
		}

		return GetEncryptionAlgorithm().LevelReduce(cipherText1, linearKeySwitchHint);
	}

	/**
	* perform RingReduce on a vector of ciphertext
	* @param ciphertext - vector of ciphertext
	* @param &keySwitchHint - is the keySwitchHint from original private key to sparse private key
	*/

	void RingReduce(
		std::vector<shared_ptr<Ciphertext<Element>>> ciphertext,
		const shared_ptr<LPEvalKeyNTRU<Element>> keySwitchHint)
	{
		if( keySwitchHint->GetCryptoContext() != *this )
			throw std::logic_error("Key passed to RingReduce was not generated with this crypto context");

		for (int i = 0; i < ciphertext.size(); i++) {
			if( ciphertext.at(i)->GetCryptoContext() != *this )
				throw std::logic_error("Ciphertext passed to RingReduce was not generated with this crypto context");

			GetEncryptionAlgorithm().RingReduce(ciphertext[i], keySwitchHint);
		}

		return;
	}

	/**
	* perform ComposedEvalMult
	* @param ciphertext1 - first cipher text
	* @param ciphertext2 - second cipher text
	* @param &quadKeySwitchHint - is the quadratic key switch hint from original private key to the quadratic key
	* @param ciphertextResult - resulting ciphertext
	*/
	std::vector<shared_ptr<Ciphertext<Element>>> ComposedEvalMult(
		const std::vector<shared_ptr<Ciphertext<Element>>> ciphertext1,
		const std::vector<shared_ptr<Ciphertext<Element>>> ciphertext2,
		const shared_ptr<LPEvalKeyNTRU<Element>> quadKeySwitchHint)
	{
		if (ciphertext1.size() != ciphertext2.size()) {
			throw std::logic_error("Cannot have ciphertext of different length");
		}

		if( quadKeySwitchHint->GetCryptoContext() != *this )
			throw std::logic_error("Key passed to ComposedEvalMult was not generated with this crypto context");

		vector<shared_ptr<Ciphertext<Element>>> ciphertextResult;

		for (int i = 0; i < ciphertext1.size(); i++) {
			if( ciphertext1.at(i)->GetCryptoContext() != *this || ciphertext2.at(i)->GetCryptoContext() != *this )
				throw std::logic_error("Ciphertext passed to KeySwitch was not generated with this crypto context");

			shared_ptr<Ciphertext<Element>> e = GetEncryptionAlgorithm().ComposedEvalMult(ciphertext1.at(i), ciphertext2.at(i), quadKeySwitchHint);
			ciphertextResult.push_back( e );
		}

		return ciphertextResult;
	}

	shared_ptr<LPPublicKey<Element>>	deserializePublicKey(const Serialized& serObj);
	shared_ptr<LPPrivateKey<Element>>	deserializeSecretKey(const Serialized& serObj);
	shared_ptr<Ciphertext<Element>>		deserializeCiphertext(const Serialized& serObj);
	shared_ptr<LPEvalKey<Element>>		deserializeEvalKey(const Serialized& serObj);
};

template <class Element>
class CryptoContextFactory {
public:
	static CryptoContext<Element> genCryptoContextLTV(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
			usint relinWindow, float stDev, int depth = 1);

	static CryptoContext<Element> genCryptoContextBV(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
			usint relinWindow, float stDev);

	// FIXME: this is temporary until we better incorporate DCRT
	static CryptoContext<Element> getCryptoContextDCRT(LPCryptoParametersLTV<ILVectorArray2n>* cryptoParams);

	static CryptoContext<Element> genCryptoContextStehleSteinfeld(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
			usint relinWindow, float stDev, float stDevStSt);

	static CryptoContext<Element> getCryptoContextNull(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity);

	// helpers for deserialization of contexts
	static shared_ptr<LPCryptoParameters<Element>> GetParameterObject( const Serialized& serObj ) {

		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersType");
		if( mIter != serObj.MemberEnd() ) {
			string parmstype = mIter->value;

			if( parmstype == "LPCryptoParametersLTV") {
				return shared_ptr<LPCryptoParameters<Element>>( new LPCryptoParametersLTV<Element>() );
			}
			else if( parmstype == "LPCryptoParametersBV") {
				return shared_ptr<LPCryptoParameters<Element>>( new LPCryptoParametersBV<Element>() );
			}
			else if( parmstype == "LPCryptoParametersDCRT") { // fixme
				return shared_ptr<LPCryptoParameters<Element>>();
			}
			else if( parmstype == "LPCryptoParametersStehleSteinfeld") {
				return shared_ptr<LPCryptoParameters<Element>>( new LPCryptoParametersStehleSteinfeld<Element>() );
			}
			else if( parmstype == "LPCryptoParametersNull" ) {
				return shared_ptr<LPCryptoParameters<Element>>( new LPCryptoParametersNull<Element>() );
			}
		}

		return shared_ptr<LPCryptoParameters<Element>>();
	}

	static CryptoContext<Element> DeserializeAndCreateContext( const Serialized& serObj ) {
		shared_ptr<LPCryptoParameters<Element>> cp = GetParameterObject(serObj);

		if( cp == false ) {
			throw std::logic_error("Unable to create crypto parameters");
		}

		if( cp->Deserialize(serObj) ) {
			return CryptoContext<Element>( new CryptoContextImpl<Element>(cp) );
		}

		throw std::logic_error("Unable to deserialize crypto parameters");
	}

	static bool DeserializeAndValidateParams( const CryptoContext<Element> ctx, const Serialized& serObj ) {
		shared_ptr<LPCryptoParameters<Element>> cp = GetParameterObject(serObj);

		if( typeid(cp) != typeid(ctx.GetCryptoParameters()) ) {
			return false;
		}

		if( cp == false ) {
			return false;
		}

		if( cp->Deserialize(serObj) == false ) {
			return false;
		}

		return false; //CryptoContext<Element>( new CryptoContextImpl<Element>(cp) );
	}
};


}

#endif /* SRC_DEMO_PRE_CRYPTOCONTEXT_H_ */
