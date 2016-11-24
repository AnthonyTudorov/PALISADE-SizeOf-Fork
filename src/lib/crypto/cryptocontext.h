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

/**
 * @brief CryptoContextImpl Class.
 *
 * This class implements a container for the Crypto Context.
 * Every object in Palisade is created within a context and
 * maintains a shared pointer to its context
 */

template <class Element>
class CryptoContextFactory;

/**
 * @brief CryptoContext
 *
 * A CryptoContext is the object used to access the PALISADE library
 *
 * All PALISADE functionality is accessed by way of an instance of a CryptoContext; we say that various objects are
 * "created in" a context, and can only be used in the context in which they were created
 *
 * All PALISADE methods are accessed through CryptoContext methods. Guards are implemented to make certain that
 * only valid objects that have been created in the context are used
 *
 * Contexts are created using the CryptoContextFactory, and can be serialized and recovered from a serialization
 */
template <class Element>
class CryptoContext : public Serializable {
	friend class CryptoContextFactory<Element>;

private:
	shared_ptr<LPCryptoParameters<Element>>				params;	/*!< crypto parameters used for this context */
	shared_ptr<LPPublicKeyEncryptionScheme<Element>>	scheme;	/*!< algorithm used; accesses all crypto methods */

	/**
	 * Private methods to compare two contexts; this is only used internally and is not generally available
	 * @param a
	 * @param b
	 * @return true if the parameters match (no need to check schemes)
	 */
	friend bool operator==(const CryptoContext<Element>& a, const CryptoContext<Element>& b) { return a.params == b.params; }
	friend bool operator!=(const CryptoContext<Element>& a, const CryptoContext<Element>& b) { return a.params != b.params; }

public:
	/**
	 * CryptoContext constructor from pointers to parameters and scheme
	 * @param params - pointer to CryptoParameters
	 * @param scheme - pointer to Crypto Scheme
	 */
	CryptoContext(LPCryptoParameters<Element> *params = 0, LPPublicKeyEncryptionScheme<Element> *scheme = 0) {
		this->params.reset(params);
		this->scheme.reset(scheme);
	}

	/**
	 * CryptoContext constructor from shared pointers to parameters and scheme
	 * @param params - shared pointer to CryptoParameters
	 * @param scheme - sharedpointer to Crypto Scheme
	 */
	CryptoContext(shared_ptr<LPCryptoParameters<Element>> params, shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme) {
		this->params = params;
		this->scheme = scheme;
	}

	/**
	 * Copy constructor
	 * @param c
	 */
	CryptoContext(const CryptoContext<Element>& c) {
		params = c.params;
		scheme = c.scheme;
	}

	/**
	 * Assignment
	 * @param rhs
	 * @return
	 */
	CryptoContext<Element>& operator=(const CryptoContext<Element>& rhs) {
		params = rhs.params;
		scheme = rhs.scheme;
		return *this;
	}

	/**
	 * A CryptoContext is only valid if the shared pointers are both valid
	 */
	operator bool() const { return bool(params) && bool(scheme); }

	/**
	 * Serialize the CryptoContext
	 *
	 * @param serObj - rapidJson object for the serializaion
	 * @return true on success
	 */
	bool Serialize(Serialized* serObj) const { return params->Serialize(serObj); }

	/**
	 * Deserialize the context AND initialize the algorithm
	 *
	 * @param serObj
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj);

	/**
	 * Enable a particular feature for use with this CryptoContext
	 * @param feature - the feature that should be enabled
	 */
	void Enable(PKESchemeFeature feature) { scheme->Enable(feature); }

	/**
	 * Getter for Scheme
	 * @return scheme
	 */
	const shared_ptr<LPPublicKeyEncryptionScheme<Element>> GetEncryptionAlgorithm() const { return scheme; }

	/**
	 * Getter for CryptoParams
	 * @return params
	 */
	const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return params; }

	/**
	 * Getter for the Discrete Gaussian Generator used by the params
	 * @return reference to the generator
	 */
	const DiscreteGaussianGenerator& GetGenerator() const { return params->GetDiscreteGaussianGenerator(); }

	/**
	 * FIXME this should go away soon
	 * @return
	 */
	const shared_ptr<ILParams> GetElementParams() {
		return std::dynamic_pointer_cast<ILParams>(params->GetElementParams());
	}

	/**
	 * KeyGen generates a key pair using this algorithm's KeyGen method
	 * @return a public/secret key pair
	 */
	LPKeyPair<Element> KeyGen() const {
		return GetEncryptionAlgorithm()->KeyGen(*this);
	}

	/**
	 * FIXME this comment needs help
	 * @return a public/secret key pair
	 */
	LPKeyPair<Element> SparseKeyGen() const {
		return GetEncryptionAlgorithm()->SparseKeyGen(*this);
	}

	/**
	 * ReKeyGen produces an Eval Key that PALISADE can use for Proxy Re Encryption
	 * @param PublicKey
	 * @param PrivateKey
	 * @return new evaluation key
	 */
	shared_ptr<LPEvalKey<Element>> ReKeyGen(
			const shared_ptr<LPPublicKey<Element>> PublicKey,
			const shared_ptr<LPPrivateKey<Element>> PrivateKey) const {

		if( !PublicKey || !PrivateKey || PublicKey->GetCryptoContext() != *this || PrivateKey->GetCryptoContext() != *this )
			throw std::logic_error("Keys passed to ReKeyGen were not generated with this crypto context");

		return GetEncryptionAlgorithm()->ReKeyGen(PublicKey, PrivateKey);
	}

	/**
	 * EvalMultKeyGen creates a key that can be used with the EvalMult operator
	 * @param key
	 * @return new evaluation key
	 */
	shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> key) const {

		if( !key || key->GetCryptoContext() != *this )
			throw std::logic_error("Key passed to EvalMultKeyGen were not generated with this crypto context");

		return GetEncryptionAlgorithm()->EvalMultKeyGen(key);
	}

	/**
	 * KeySwitchGen creates a key that can be used with the KeySwitch operation
	 * @param key1
	 * @param key2
	 * @return new evaluation key
	 */
	shared_ptr<LPEvalKey<Element>> KeySwitchGen(
			const shared_ptr<LPPrivateKey<Element>> key1, const shared_ptr<LPPrivateKey<Element>> key2) const {

		if( !key1 || !key2 || key1->GetCryptoContext() != *this || key2->GetCryptoContext() != *this )
			throw std::logic_error("Keys passed to KeySwitchGen were not generated with this crypto context");

		return GetEncryptionAlgorithm()->KeySwitchGen(key1, key2);
	}

	/**
	 * QuadraticEvalMultKeyGen creates the key that can be used with Quadratic EvalMult
	 * @param k1
	 * @param k2
	 * @return new evaluation key
	 */
	shared_ptr<LPEvalKeyNTRU<Element>> QuadraticEvalMultKeyGen(
			const shared_ptr<LPPrivateKey<Element>> k1,
			const shared_ptr<LPPrivateKey<Element>> k2) const {

		if( !k1 || !k2 || k1->GetCryptoContext() != *this || k2->GetCryptoContext() != *this )
			throw std::logic_error("Keys passed to QuadraticEvalMultKeyGen were not generated with this crypto context");

		return GetEncryptionAlgorithm()->QuadraticEvalMultKeyGen(k1, k2);
	}

	/**
	 * Encrypt method for PALISADE
	 * @param publicKey - for encryption
	 * @param plaintext - to encrypt
	 * @param doPadding - if true, pad the input out to fill the encrypted chunk
	 * @return a vector of pointers to Ciphertexts created by encrypting the plaintext
	 */
	std::vector<shared_ptr<Ciphertext<Element>>> Encrypt(
			const shared_ptr<LPPublicKey<Element>> publicKey,
			const Plaintext& plaintext,
			bool doPadding = true)
	{
		std::vector<shared_ptr<Ciphertext<Element>>> cipherResults;

		if( !publicKey || publicKey->GetCryptoContext() != *this )
			throw std::logic_error("key passed to Encrypt was not generated with this crypto context");

		const BigBinaryInteger& ptm = publicKey->GetCryptoParameters()->GetPlaintextModulus();
		size_t chunkSize = plaintext.GetChunksize(publicKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(), ptm);
		size_t ptSize = plaintext.GetLength();
		size_t rounds = ptSize/chunkSize;

		if( doPadding == false && ptSize%chunkSize != 0
				&& typeid(plaintext) == typeid(BytePlaintextEncoding)) {
			throw std::logic_error("Cannot Encrypt without padding with chunksize " + std::to_string(chunkSize) + " and plaintext size " + std::to_string(ptSize));
		}

		// if there is a partial chunk OR if there isn't but we need to pad
		if( ptSize%chunkSize != 0 || doPadding == true )
			rounds += 1;

		for( int bytes=0, i=0; i < rounds ; bytes += chunkSize,i++ ) {

			Element pt(publicKey->GetCryptoParameters()->GetElementParams());
			plaintext.Encode(ptm, &pt, bytes, chunkSize);

			shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey,pt);

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
		if( !publicKey || publicKey->GetCryptoContext() != *this )
			throw std::logic_error("key passed to EncryptStream was not generated with this crypto context");

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

			shared_ptr<Ciphertext<Element>> ciphertext = GetEncryptionAlgorithm()->Encrypt(publicKey, pt);
			if( !ciphertext ) {
				delete ptxt;
				return;
			}

			Serialized cS;

			if( ciphertext->Serialize(&cS) ) {
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

	/**
	 * Decrypt method for PALISADE
	 * @param privateKey - for decryption
	 * @param ciphertext - vector of encrypted ciphertext
	 * @param plaintext - pointer to destination for the result of decryption
	 * @param doPadding - true if input plaintext was padded; causes unpadding on last piece of ciphertext
	 * @return size of plaintext
	 */
	DecryptResult Decrypt(
			const shared_ptr<LPPrivateKey<Element>> privateKey,
			const std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext,
			Plaintext *plaintext,
			bool doPadding = true)
	{
		// edge case
		if( ciphertext.size() == 0 )
			return DecryptResult();

		if( !privateKey || privateKey->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to Decrypt was not generated with this crypto context");

		int lastone = ciphertext.size() - 1;
		for( int ch = 0; ch < ciphertext.size(); ch++ ) {
			if( !ciphertext[ch] || ciphertext[ch]->GetCryptoContext() != *this )
				throw std::logic_error("A ciphertext passed to Decrypt was not generated with this crypto context");

			Element decrypted;
			DecryptResult result = GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext[ch], &decrypted);

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
		if( !privateKey || privateKey->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to Decrypt was not generated with this crypto context");

		Serialized serObj;
		size_t tot = 0;

		bool firstTime = true;
		BytePlaintextEncoding pte[2];
		bool whichArray = false;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			shared_ptr<Ciphertext<Element>> ct;
			if( ct = deserializeCiphertext(serObj) ) {
				Element decrypted;
				DecryptResult res = GetEncryptionAlgorithm()->Decrypt(privateKey, ct, &decrypted);
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

	/**
	 * ReEncrypt - Proxy Re Encryption mechanism for PALISADE
	 * @param evalKey - evaluation key from the PRE keygen method
	 * @param ciphertext - vector of shared pointers to encrypted Ciphertext
	 * @return vector of shared pointers to re-encrypted ciphertexts
	 */
	std::vector<shared_ptr<Ciphertext<Element>>> ReEncrypt(
			shared_ptr<LPEvalKey<Element>> evalKey,
			std::vector<shared_ptr<Ciphertext<Element>>>& ciphertext)
	{
		if( !evalKey || evalKey->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to ReEncrypt was not generated with this crypto context");

		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext;
		for( int i=0; i < ciphertext.size(); i++ ) {
			if( !ciphertext[i] || ciphertext[i]->GetCryptoContext() != *this )
				throw std::logic_error("One of the ciphertexts passed to ReEncrypt was not generated with this crypto context");
			newCiphertext.push_back( GetEncryptionAlgorithm()->ReEncrypt(evalKey, ciphertext[i]) );
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
		if( !evalKey || evalKey->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to ReEncrypt was not generated with this crypto context");

		Serialized serObj;

		while( SerializableHelper::StreamToSerialization(instream, &serObj) ) {
			shared_ptr<Ciphertext<Element>> ct;
			ct = deserializeCiphertext(serObj);
			if( ct ) {
				std::vector<shared_ptr<Ciphertext<Element>>> allCt;
				allCt.push_back(ct);
				std::vector<shared_ptr<Ciphertext<Element>>> reCt = ReEncrypt(evalKey, allCt);

				Serialized serReObj;
				if( reCt[0]->Serialize(&serReObj) ) {
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

	/**
	 * EvalAdd - PALISADE EvalAdd method for a pair of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 + ct2
	 */
	shared_ptr<Ciphertext<Element>>
	EvalAdd(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2)
	{
		if( !ct1 || !ct2 || ct1->GetCryptoContext() != *this || ct2->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to EvalAdd was not generated with this crypto context");

		return GetEncryptionAlgorithm()->EvalAdd(ct1, ct2);
	}

	/**
	 * EvalSub - PALISADE EvalSub method for a pair of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 - ct2
	 */
	shared_ptr<Ciphertext<Element>>
	EvalSub(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2)
	{
		if( !ct1 || !ct2 || ct1->GetCryptoContext() != *this || ct2->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to EvalSub was not generated with this crypto context");

		return GetEncryptionAlgorithm()->EvalSub(ct1, ct2);
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts
	 * @param ct1
	 * @param ct2
	 * @return new ciphertext for ct1 * ct2
	 */
	shared_ptr<Ciphertext<Element>>
	EvalMult(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2)
	{
		if( !ct1 || !ct2 || ct1->GetCryptoContext() != *this || ct2->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to EvalMult was not generated with this crypto context");

		return GetEncryptionAlgorithm()->EvalMult(ct1, ct2);
	}

	/**
	 * EvalMult - PALISADE EvalMult method for a pair of ciphertexts, followed by recrypt with given key
	 * @param ct1
	 * @param ct2
	 * @param ek
	 * @return new ciphertext for ct1 * ct2, recrypted with ek
	 */
	shared_ptr<Ciphertext<Element>>
	EvalMult(const shared_ptr<Ciphertext<Element>> ct1, const shared_ptr<Ciphertext<Element>> ct2, const shared_ptr<LPEvalKey<Element>> ek)
	{
		if( !ct1 || !ct2 || !ek || ct1->GetCryptoContext() != *this || ct2->GetCryptoContext() != *this || ek->GetCryptoContext() != *this )
			throw std::logic_error("Information passed to EvalMult was not generated with this crypto context");

		return GetEncryptionAlgorithm()->EvalMult(ct1, ct2, ek);
	}

	/**
	* KeySwitch - PALISADE KeySwitch method
	* @param keySwitchHint - reference to KeySwitchHint
	* @param ciphertext - vector of ciphertext
	* @return new Ciphertext after applying key switch
	*/
	shared_ptr<Ciphertext<Element>> KeySwitch(
		const shared_ptr<LPEvalKey<Element>> keySwitchHint,
		const shared_ptr<Ciphertext<Element>> ciphertext)
	{
		if( !keySwitchHint || keySwitchHint->GetCryptoContext() != *this )
			throw std::logic_error("Key passed to KeySwitch was not generated with this crypto context");

		if( !ciphertext || ciphertext->GetCryptoContext() != *this )
			throw std::logic_error("Ciphertext passed to KeySwitch was not generated with this crypto context");

		return GetEncryptionAlgorithm()->KeySwitch(keySwitchHint, ciphertext);
	}

	/**
	* ModReduce - PALISADE ModReduce method
	* @param ciphertext - vector of ciphertext
	* @return vector of mod reduced ciphertext
	*/
	std::vector<shared_ptr<Ciphertext<Element>>> ModReduce(
		vector<shared_ptr<Ciphertext<Element>>> ciphertext)
	{
		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext(ciphertext.size());

		for (int i = 0; i < ciphertext.size(); i++) {
			if( !ciphertext[i] || ciphertext[i]->GetCryptoContext() != *this )
				throw std::logic_error("Information passed to ModReduce was not generated with this crypto context");

			newCiphertext[i] = GetEncryptionAlgorithm()->ModReduce(ciphertext[i]);
		}

		return std::move(newCiphertext);
	}

	/**
	 * LevelReduce - PALISADE LevelReduce method
	 * @param cipherText1
	 * @param linearKeySwitchHint
	* @return vector of level reduced ciphertext
	 */
	shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
			const shared_ptr<LPEvalKeyNTRU<Element>> linearKeySwitchHint) const {

		if( !cipherText1 || !linearKeySwitchHint || cipherText1->GetCryptoContext() != *this || linearKeySwitchHint->GetCryptoContext() != *this) {
			throw std::logic_error("Information passed to LevelReduce was not generated with this crypto context");
		}

		return GetEncryptionAlgorithm()->LevelReduce(cipherText1, linearKeySwitchHint);
	}

	/**
	* RingReduce - PALISADE RingReduce method
	* @param ciphertext - vector of ciphertext
	* @param keySwitchHint - the keySwitchHint from original private key to sparse private key
	* @return vector of ring-reduced ciphertexts
	*/

	std::vector<shared_ptr<Ciphertext<Element>>> RingReduce(
		std::vector<shared_ptr<Ciphertext<Element>>> ciphertext,
		const shared_ptr<LPEvalKey<Element>> keySwitchHint)
	{
		if( !keySwitchHint || keySwitchHint->GetCryptoContext() != *this )
			throw std::logic_error("Key passed to RingReduce was not generated with this crypto context");

		std::vector<shared_ptr<Ciphertext<Element>>> newCiphertext(ciphertext.size());

		for (int i = 0; i < ciphertext.size(); i++) {
			if( !ciphertext[i] || ciphertext[i]->GetCryptoContext() != *this )
				throw std::logic_error("Ciphertext passed to RingReduce was not generated with this crypto context");

			newCiphertext[i] = GetEncryptionAlgorithm()->RingReduce(ciphertext[i], keySwitchHint);
		}

		return newCiphertext;
	}

	/**
	* ComposedEvalMult - PALISADE composed evalmult
	* @param ciphertext1 - vector for first cipher text
	* @param ciphertext2 - vector for second cipher text
	* @param quadKeySwitchHint - is the quadratic key switch hint from original private key to the quadratic key
	* return vector of resulting ciphertext
	*/
	std::vector<shared_ptr<Ciphertext<Element>>> ComposedEvalMult(
		const std::vector<shared_ptr<Ciphertext<Element>>> ciphertext1,
		const std::vector<shared_ptr<Ciphertext<Element>>> ciphertext2,
		const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint)
	{
		if( !quadKeySwitchHint || quadKeySwitchHint->GetCryptoContext() != *this) {
			throw std::logic_error("Information passed to ComposedEvalMult was not generated with this crypto context");
		}
		if (ciphertext1.size() != ciphertext2.size()) {
			throw std::logic_error("Cannot have ciphertext of different length");
		}

		vector<shared_ptr<Ciphertext<Element>>> ciphertextResult;

		for (int i = 0; i < ciphertext1.size(); i++) {
			if( !ciphertext1[i] || !ciphertext2[i] || ciphertext1[i]->GetCryptoContext() != *this || ciphertext2[i]->GetCryptoContext() != *this )
				throw std::logic_error("Ciphertext passed to KeySwitch was not generated with this crypto context");

			shared_ptr<Ciphertext<Element>> e = GetEncryptionAlgorithm()->ComposedEvalMult(ciphertext1[i], ciphertext2[i], quadKeySwitchHint);
			ciphertextResult.push_back( e );
		}

		return ciphertextResult;
	}

	/**
	 * Deserialize into a Public Key
	 * @param serObj
	 * @return deserialized object
	 */
	shared_ptr<LPPublicKey<Element>>	deserializePublicKey(const Serialized& serObj);

	/**
	 * Deserialize into a Private Key
	 * @param serObj
	 * @return deserialized object
	 */
	shared_ptr<LPPrivateKey<Element>>	deserializeSecretKey(const Serialized& serObj);

	/**
	 * Deserialize into a Ciphertext
	 * @param serObj
	 * @return deserialized object
	 */
	shared_ptr<Ciphertext<Element>>		deserializeCiphertext(const Serialized& serObj);

	/**
	 * Deserialize into an Eval Key
	 * @param serObj
	 * @return deserialized object
	 */
	shared_ptr<LPEvalKey<Element>>		deserializeEvalKey(const Serialized& serObj);

	/**
	 * Deserialize into an EvalMult Key
	 * @param serObj
	 * @return deserialized object
	 */
	shared_ptr<LPEvalKey<Element>>		deserializeEvalMultKey(const Serialized& serObj);
};


/**
 * @brief CryptoContextFactory
 *
 * A class that contains static methods to generate new crypto contexts from user parameters
 *
 */
template <class Element>
class CryptoContextFactory {
public:
	static CryptoContext<Element> genCryptoContextLTV(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
			usint relinWindow, float stDev, int depth = 1);

	static CryptoContext<Element> genCryptoContextFV(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
			usint relinWindow, float stDev, const std::string& delta,
			MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
			int depth = 0, int assuranceMeasure = 0, float securityLevel = 0);

	static CryptoContext<Element> genCryptoContextFV(
			const BigBinaryInteger& plaintextModulus, float securityLevel,
			unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches);

	static CryptoContext<Element> genCryptoContextBV(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
			usint relinWindow, float stDev);

	//temp function written by GRS
	static CryptoContext<Element> genCryptoContextBV(LPCryptoParametersBV<Element>* cryptoParams);

	// FIXME: this is temporary until we better incorporate DCRT
	static CryptoContext<Element> getCryptoContextDCRT(LPCryptoParametersLTV<ILVectorArray2n>* cryptoParams);

	static CryptoContext<Element> genCryptoContextStehleSteinfeld(
			const usint plaintextmodulus,
			usint ringdim, const std::string& modulus, const std::string& rootOfUnity,
			usint relinWindow, float stDev, float stDevStSt);

	static CryptoContext<Element> getCryptoContextNull(
			const usint modulus,
			usint ringdim);

	// helpers for deserialization of contexts
	static shared_ptr<LPCryptoParameters<Element>> GetParameterObject( const Serialized& serObj ) {

		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersType");
		if( mIter != serObj.MemberEnd() ) {
			string parmstype = mIter->value.GetString();

			if( parmstype == "LPCryptoParametersLTV") {
				return shared_ptr<LPCryptoParameters<Element>>( new LPCryptoParametersLTV<Element>() );
			}
			else if( parmstype == "LPCryptoParametersBV") {
				return shared_ptr<LPCryptoParameters<Element>>( new LPCryptoParametersBV<Element>() );
			}
			else if( parmstype == "LPCryptoParametersFV") {
				return shared_ptr<LPCryptoParameters<Element>>( new LPCryptoParametersFV<Element>() );
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

	static shared_ptr<LPPublicKeyEncryptionScheme<Element>> GetSchemeObject( const Serialized& serObj ) {

		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersType");
		if( mIter != serObj.MemberEnd() ) {
			string parmstype = mIter->value.GetString();

			if( parmstype == "LPCryptoParametersLTV") {
				return shared_ptr<LPPublicKeyEncryptionScheme<Element>>( new LPPublicKeyEncryptionSchemeLTV<Element>() );
			}
			else if( parmstype == "LPCryptoParametersBV") {
				return shared_ptr<LPPublicKeyEncryptionScheme<Element>>( new LPPublicKeyEncryptionSchemeBV<Element>() );
			}
			else if( parmstype == "LPCryptoParametersFV") {
				return shared_ptr<LPPublicKeyEncryptionScheme<Element>>( new LPPublicKeyEncryptionSchemeFV<Element>() );
			}
			else if( parmstype == "LPCryptoParametersDCRT") { // fixme
				return shared_ptr<LPPublicKeyEncryptionScheme<Element>>( new LPPublicKeyEncryptionSchemeLTV<Element>());
			}
			else if( parmstype == "LPCryptoParametersStehleSteinfeld") {
				return shared_ptr<LPPublicKeyEncryptionScheme<Element>>( new LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>() );
			}
			else if( parmstype == "LPCryptoParametersNull" ) {
				return shared_ptr<LPPublicKeyEncryptionScheme<Element>>( new LPPublicKeyEncryptionSchemeNull<Element>() );
			}
		}

		return shared_ptr<LPPublicKeyEncryptionScheme<Element>>();
	}

	static CryptoContext<Element> DeserializeAndCreateContext( const Serialized& serObj ) {
		shared_ptr<LPCryptoParameters<Element>> cp = GetParameterObject(serObj);

		if( cp == false ) {
			throw std::logic_error("Unable to create crypto parameters");
		}

		if( !cp->Deserialize(serObj) ) {
			throw std::logic_error("Unable to deserialize crypto parameters");
		}

		shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme = GetSchemeObject(serObj);

		CryptoContext<Element> cc( cp, scheme );
		return cc;
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
