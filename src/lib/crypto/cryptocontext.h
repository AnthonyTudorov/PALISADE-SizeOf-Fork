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
//#include "../encoding/byteplaintextencoding.h"

namespace lbcrypto {

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
	/* these variables are used to initialize the CryptoContext - if they are not used they can get ditched */
	usint				ringdim;		/*!< ring dimension */
	BigBinaryInteger	ptmod;			/*!< plaintext modulus */

	/* these three parameters get initialized when an instance is constructed; they are used by the context */
	DiscreteGaussianGenerator	dgg;
	DiscreteGaussianGenerator	dggStSt;	// unused unless we use StSt scheme

	shared_ptr<LPCryptoParameters<Element>>	params;	/*!< crypto parameters used for this context */
	LPPublicKeyEncryptionScheme<Element>	*scheme;	/*!< algorithm used; points to keygen and encrypt/decrypt methods */

	CryptoContextImpl() : scheme(0), ringdim(0) {}
	CryptoContextImpl(shared_ptr<LPCryptoParameters<Element>> cp) : params(cp), scheme(0), ringdim(0) {}

public:
	~CryptoContextImpl() {
		if( scheme ) delete scheme;
	}

	DiscreteGaussianGenerator& GetGenerator() { return dgg; }
	//ILParams& GetILParams() { return *elemParams; }

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

	/**
	 *
	 * @return amount of padding that must be added
	 */
	usint getPadAmount() const { return ringdim/16 * (ptmod.GetMSB()-1); }

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

	CryptoContext() {}

	CryptoContext(CryptoContextImpl<Element> *e) {
		ctx.reset( e );
	}

	CryptoContext(const CryptoContext<Element>& c) {
		ctx = c.ctx;
	}

	CryptoContext<Element>& operator=(const CryptoContext<Element>& rhs) {
		ctx = rhs.ctx;
		return *this;
	}

	void Enable(PKESchemeFeature feature) { ctx->getScheme()->Enable(feature); }

	const LPPublicKeyEncryptionScheme<Element> &GetEncryptionAlgorithm() const { return *ctx->getScheme(); }

	const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return ctx->getCryptoParams(); }

	DiscreteGaussianGenerator& GetGenerator() { return ctx->GetGenerator(); }

	//ILParams& GetILParams() { return ctx->GetILParams(); }

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

	std::vector<shared_ptr<Ciphertext<Element>>> Encrypt(
			const shared_ptr<LPPublicKey<Element>> publicKey,
			const Plaintext& plaintext,
			bool doPadding = true)
	{
		std::vector<shared_ptr<Ciphertext<Element>>> cipherResults;

		if( publicKey->GetCryptoContext() != *this )
			throw std::logic_error("key passed to Encrypt was not generated with this crypto context");

		const BigBinaryInteger& ptm = publicKey->GetCryptoParameters().GetPlaintextModulus();
		size_t chunkSize = plaintext.GetChunksize(publicKey->GetCryptoParameters().GetElementParams()->GetCyclotomicOrder(), ptm);
		size_t ptSize = plaintext.GetLength();
		size_t rounds = ptSize/chunkSize;

		if( doPadding == false && ptSize%chunkSize != 0 ) {
			throw std::logic_error("Cannot Encrypt without padding with this plaintext size");
		}

		// if there is a partial chunk OR if there isn't but we need to pad
		if( ptSize%chunkSize != 0 || doPadding == true )
			rounds += 1;

		for( int bytes=0, i=0; i < rounds ; bytes += chunkSize,i++ ) {

			Element pt(publicKey->GetCryptoParameters().GetElementParams());
			plaintext.Encode(ptm, &pt, bytes, chunkSize);
			pt.SwitchFormat();

			shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm().Encrypt(publicKey,pt);

			if( !ciphertext ) {
				cipherResults.clear();
				break;
			}

			cipherResults.push_back(ciphertext);

		}

		return cipherResults;
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

			plaintext->Decode(privateKey->GetCryptoParameters().GetPlaintextModulus(), &decrypted);

			if( ch == lastone && doPadding ) {
				plaintext->Unpad(privateKey->GetCryptoParameters().GetPlaintextModulus());
			}
		}

		return DecryptResult(plaintext->GetLength());
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
	* perform KeySwitch on a vector of ciphertext
	* @param scheme - a reference to the encryption scheme in use
	* @param keySwitchHint - reference to KeySwitchHint
	* @param ciphertext - vector of ciphertext
	*/
	std::vector<shared_ptr<Ciphertext<Element>>> KeySwitch(
		const shared_ptr<LPEvalKeyNTRU<Element>> keySwitchHint,
		const vector<shared_ptr<Ciphertext<Element>>>& ciphertext)
	{
		if( keySwitchHint->GetCryptoContext() != *this )
			throw std::logic_error("Key passed to KeySwitch was not generated with this crypto context");

		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext;

		for (int i = 0; i < ciphertext.size(); i++) {
			if( ciphertext.at(i)->GetCryptoContext() != *this )
				throw std::logic_error("Ciphertext passed to KeySwitch was not generated with this crypto context");

			newCiphertext->push_back( GetEncryptionAlgorithm().KeySwitch(keySwitchHint, ciphertext[i]) );
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
		for (int i = 0; i < ciphertext->size(); i++) {
			if( ciphertext.at(i)->GetCryptoContext() != *this )
				throw std::logic_error("Information passed to KeySwitch was not generated with this crypto context");

			ciphertext[i] = GetEncryptionAlgorithm().ModReduce(ciphertext[i]);
		}

		return ciphertext;
	}

	/**
	* perform RingReduce on a vector of ciphertext
	* @param &scheme - a reference to the encryption scheme in use
	* @param ciphertext - vector of ciphertext
	* @param &keySwitchHint - is the keySwitchHint from original private key to sparse private key
	*/

	std::vector<shared_ptr<Ciphertext<Element>>> RingReduce(
		std::vector<shared_ptr<Ciphertext<Element>>> ciphertext,
		const shared_ptr<LPEvalKeyNTRU<Element>> keySwitchHint)
	{
		if( keySwitchHint->GetCryptoContext() != *this )
			throw std::logic_error("Key passed to KeySwitch was not generated with this crypto context");

		for (int i = 0; i < ciphertext->size(); i++) {
			if( ciphertext.at(i)->GetCryptoContext() != *this )
				throw std::logic_error("Ciphertext passed to KeySwitch was not generated with this crypto context");

			ciphertext[i] = GetEncryptionAlgorithm().RingReduce(ciphertext[i], keySwitchHint);
		}

		return ciphertext;
	}

	/**
	* perform RingReduce on a vector of ciphertext
	* @param &scheme - a reference to the encryption scheme in use
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

			ciphertextResult.push_back( GetEncryptionAlgorithm().ComposedEvalMult(ciphertext1.at(i), ciphertext2.at(i), quadKeySwitchHint) );
		}

		return ciphertextResult;
	}

};

template <class Element>
class CryptoContextFactory {
public:
	static CryptoContext<Element> genCryptoContextLTV(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
			usint relinWindow, float stDev);

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

	static CryptoContext<Element> getCryptoContextNull();

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
				return shared_ptr<LPCryptoParameters<Element>>( new LPCryptoParametersBV<Element>() );
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
