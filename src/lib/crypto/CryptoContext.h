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
* This file defines the Crypto Context: all the pieces needed to use the palisade library
*/

#ifndef SRC_DEMO_PRE_CRYPTOCONTEXT_H_
#define SRC_DEMO_PRE_CRYPTOCONTEXT_H_

#include <string>

#include "../math/backend.h"
#include "../utils/inttypes.h"

#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"

#include "../crypto/lwecrypt.h"
#include "../crypto/lwecrypt.cpp"
#include "../crypto/lwepre.h"
#include "../crypto/lwepre.cpp"
#include "../crypto/lweahe.h"
#include "../crypto/lweahe.cpp"
#include "../crypto/lweshe.h"
#include "../crypto/lweshe.cpp"
#include "../crypto/lwefhe.h"
#include "../crypto/lwefhe.cpp"
#include "../crypto/lweautomorph.h"
#include "../crypto/lweautomorph.cpp"

#include "../crypto/ciphertext.h"
#include "../crypto/ciphertext.cpp"

#include "../utils/serializable.h"

using namespace std;
using namespace lbcrypto;

namespace lbcrypto {

/**
 * @brief CryptoContext Class.
 *
 * An instance of this class contains all of the parameters needed to create keys and encrypt/decrypt
 */
class CryptoContext : public Serializable {
private:
	string		parmsetName;

	usint ringdim;
	BigBinaryInteger ptmod;
	BigBinaryInteger mod;
	BigBinaryInteger ru;
	usint relinWindow;
	float stDev;
	float stDevStSt;

	ILParams ilParams;
	DiscreteGaussianGenerator dgg;
	DiscreteGaussianGenerator dggStSt;

	LPCryptoParametersImpl<ILVector2n>	*params;
	LPPublicKeyEncryptionScheme<ILVector2n> *algorithm;
	long								chunksize;		// the size that this parameter set can process

	// these three members are ONLY used by the Java wrapper to cache deserialized keys
	LPPublicKeyLTV<ILVector2n>	*publicKey;
	LPPrivateKeyLTV<ILVector2n>	*privateKey;
	LPEvalKeyLTV<ILVector2n>	*evalKey;

	CryptoContext() : publicKey(0), privateKey(0), evalKey(0),
			params(0), algorithm(0), chunksize(0), relinWindow(0), ringdim(0), stDev(0), stDevStSt(0) {}

public:
	~CryptoContext() {
		if( params ) delete params;
		if( algorithm ) delete algorithm;
		if( publicKey ) delete publicKey;
		if( privateKey ) delete privateKey;
		if( evalKey ) delete evalKey;
	}

	string getParmsetName() const { return parmsetName; }

	/**
	 *
	 * @return crypto parameters
	 */
	LPCryptoParametersImpl<ILVector2n>* getParams() { return params; }

	/**
	 *
	 * @return crypto algorithm
	 */
	LPPublicKeyEncryptionScheme<ILVector2n>* getAlgorithm() { return algorithm; }

	/**
	 *
	 * @return max size that this set of parameters can encrypt
	 */
	long getChunksize() { return chunksize; }

	/**
	 *
	 * @return amount of padding that must be added
	 */
	usint getPadAmount() { return ringdim/16 * (ptmod.GetMSB()-1); }

	/**
	 * Used by the Java wrapper
	 *
	 * @param serializedKey
	 * @return true on success
	 */
	bool setPublicKey( const string& serializedKey );

	/**
	 * Used by the Java wrapper
	 *
	 * @return cached deserialized public key
	 */
	LPPublicKeyLTV<ILVector2n>	*getPublicKey() { return publicKey; }

	/**
	 * Used by the Java wrapper
	 *
	 * @param serializedKey
	 * @return true on success
	 */
	bool setPrivateKey( const string& serializedKey );

	/**
	 * Used by the Java wrapper
	 *
	 * @return cached deserialized private key
	 */
	LPPrivateKeyLTV<ILVector2n>	*getPrivateKey() { return privateKey; }

	/**
	 * Used by the Java wrapper
	 *
	 * @param serializedKey
	 * @return true on success
	 */
	bool setEvalKey( const string& serializedKey );

	/**
	 * Used by the Java wrapper
	 *
	 * @return cached deserialized evaluation key
	 */
	LPEvalKeyLTV<ILVector2n>	*getEvalKey() { return evalKey; }

	/**
	 * Factory method to make an LTV CryptoContext
	 *
	 * @param plaintextmodulus
	 * @param ringdim
	 * @param modulus
	 * @param rootOfUnity
	 * @param relinWindow
	 * @param stDev
	 * @return
	 */
	static CryptoContext *genCryptoContextLTV(
			const usint plaintextmodulus,
			usint ringdim, const string& modulus, const string& rootOfUnity,
			usint relinWindow, float stDev);

	/**
	 * Factory method to make an StSt CryptoContext
	 *
	 * @param plaintextmodulus
	 * @param ringdim
	 * @param modulus
	 * @param rootOfUnity
	 * @param relinWindow
	 * @param stDev
	 * @param stDevStSt
	 * @return
	 */
	static CryptoContext *genCryptoContextStehleSteinfeld(
			const usint plaintextmodulus,
			usint ringdim, const string& modulus, const string& rootOfUnity,
			usint relinWindow, float stDev, float stDevStSt);

	bool Serialize(Serialized* serObj, const CryptoContext* ctx=0, const std::string fileFlag = "") const;

	/**
	* Populate the object from the deserialization of the Setialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	virtual bool Deserialize(const Serialized& serObj);

};

}


#endif /* SRC_DEMO_PRE_CRYPTOCONTEXT_H_ */
