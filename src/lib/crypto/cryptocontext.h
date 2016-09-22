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

namespace lbcrypto {

/**
 * @brief CryptoContext Class.
 *
 * An instance of this class contains all of the parameters needed to create keys and encrypt/decrypt
 * Note this will want to be refactored for other schemes in the future
 */

template <class Element>
class CryptoContextFactory;

template <class Element>
class CryptoContextImpl {

	friend class CryptoContextFactory<Element>;
	friend class CryptoContext<Element>;

private:
	/* these variables are used to initialize the CryptoContext */
	usint				ringdim;		/*!< ring dimension */
	BigBinaryInteger	ptmod;			/*!< plaintext modulus */
	BigBinaryInteger	mod;			/*!< modulus */
	BigBinaryInteger	ru;				/*!< root of unity */
	usint				relinWindow;	/*!< relin window */
	float				stDev;			/*!< stamdard deviation */
	float				stDevStSt;		/*!< standard deviation for StSt uses */

	/* these three parameters get initialized when an instance is constructed; they are used by the context
	 */
	ILParams					ilParams;
	DiscreteGaussianGenerator	dgg;
	DiscreteGaussianGenerator	dggStSt;	// unused unless we use StSt scheme

	LPCryptoParameters<Element>				*params;	/*!< crypto parameters used for this context */
	LPPublicKeyEncryptionScheme<Element>	*scheme;	/*!< algorithm used; points to keygen and encrypt/decrypt methods */

	// these three members are ONLY used by the Java wrapper to cache deserialized keys
	LPPublicKey<Element>		*publicKey;
	LPPrivateKey<Element>		*privateKey;
	LPEvalKeyRelin<Element>		*evalKey;

	CryptoContextImpl() : publicKey(0), privateKey(0), evalKey(0),
			params(0), scheme(0), relinWindow(0), ringdim(0), stDev(0), stDevStSt(0) {}

public:
	~CryptoContextImpl() {
		if( params ) delete params;
		if( scheme ) delete scheme;
		if( publicKey ) delete publicKey;
		if( privateKey ) delete privateKey;
		if( evalKey ) delete evalKey;
	}

	DiscreteGaussianGenerator& GetGenerator() { return dgg; }
	ILParams& GetILParams() { return ilParams; }

	/**
	 *
	 * @return crypto parameters
	 */
	LPCryptoParameters<Element>* getParams() const { return params; }

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

	/**
	 * Used by the Java wrapper
	 *
	 * @param serializedKey
	 * @return true on success
	 */
	bool setPublicKey( const std::string& serializedKey );

	/**
	 * Used by the Java wrapper
	 *
	 * @return cached deserialized public key
	 */
	LPPublicKey<Element>	*getPublicKey() const { return publicKey; }

	/**
	 * Used by the Java wrapper
	 *
	 * @param serializedKey
	 * @return true on success
	 */
	bool setPrivateKey( const std::string& serializedKey );

	/**
	 * Used by the Java wrapper
	 *
	 * @return cached deserialized private key
	 */
	LPPrivateKey<Element>	*getPrivateKey() const { return privateKey; }

	/**
	 * Used by the Java wrapper
	 *
	 * @param serializedKey
	 * @return true on success
	 */
	bool setEvalKey( const std::string& serializedKey );

	/**
	 * Used by the Java wrapper
	 *
	 * @return cached deserialized evaluation key
	 */
	LPEvalKeyRelin<Element>	*getEvalKey() const { return evalKey; }

};

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

	LPKeyPair<Element> KeyGen() const {
		return GetEncryptionAlgorithm().KeyGen(*this);
	}

	LPKeyPair<Element> SparseKeyGen() const {
		return GetEncryptionAlgorithm().SparseKeyGen(*this);
	}

	void Enable(PKESchemeFeature feature) { ctx->getScheme()->Enable(feature); }
	const LPPublicKeyEncryptionScheme<Element> &GetEncryptionAlgorithm() const { return *ctx->getScheme(); }
	const LPCryptoParameters<Element> &GetCryptoParameters() const { return *ctx->getParams(); }
	DiscreteGaussianGenerator& GetGenerator() { return ctx->GetGenerator(); }
	ILParams& GetILParams() { return ctx->GetILParams(); }

	friend bool operator==(const CryptoContext<Element>& a, const CryptoContext<Element>& b) { return a.ctx == b.ctx; }
	friend bool operator!=(const CryptoContext<Element>& a, const CryptoContext<Element>& b) { return a.ctx != b.ctx; }
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

};


}

#endif /* SRC_DEMO_PRE_CRYPTOCONTEXT_H_ */
