/**
  * @file stst.h -- definitions for StehleSteinfeld Crypto Params
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Nishanth Pasham <np386@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>, Jerry Ryan <gwryan@njit.edu>
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
 * Our Stehle-Steinfeld scheme implementation is described in http://dx.doi.org/10.1016/j.future.2016.10.013
 * It is based on the subfield lattice attack immunity condition proposed in the Conclusions of http://eprint.iacr.org/2016/127.pdf
 */

#ifndef LBCRYPTO_CRYPTO_STST_H
#define LBCRYPTO_CRYPTO_STST_H

#include "palisade.h"

namespace lbcrypto {

	//forward declarations
	template <class Element>
	class LPAlgorithmLTV;

	template <class Element>
	class LPPublicKeyEncryptionSchemeLTV;

	template <class Element>
	class LPAlgorithmPRELTV;

	template <class Element>
	class LPAlgorithmSHELTV;


/**
 * @brief Template for Stehle-Stenfeld crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersStehleSteinfeld : public LPCryptoParametersRLWE<Element> {
public:
	/**
	 * Default constructor that initializes all values to 0.
	 */
	LPCryptoParametersStehleSteinfeld() : LPCryptoParametersRLWE<Element>() {
		m_distributionParameterStSt = 0.0f;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * Copy constructor.
	 *
	 */
	LPCryptoParametersStehleSteinfeld(const LPCryptoParametersStehleSteinfeld &rhs) : LPCryptoParametersRLWE<Element>(rhs) {
		m_distributionParameterStSt = rhs.m_distributionParameterStSt;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * Constructor that initializes values.
	 *
	 * @param &params element parameters.
	 * @param &plaintextModulus plaintext modulus.
	 * @param distributionParameter noise distribution parameter.
	 * @param assuranceMeasure assurance level.
	 * @param securityLevel security level.
	 * @param relinWindow the size of the relinearization window.
	 * @param depth depth which is set to 1.
	 */
	LPCryptoParametersStehleSteinfeld(
			shared_ptr<typename Element::Params> params,
			const BigBinaryInteger &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			float distributionParmStst,
			int depth = 1)
	: LPCryptoParametersRLWE<Element>(params,
			plaintextModulus,
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {
		m_distributionParameterStSt = distributionParmStst;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}


	/**
	 * Returns the value of standard deviation r for discrete Gaussian distribution used in Key Generation
	 *
	 * @return the standard deviation r.
	 */
	float GetDistributionParameterStSt() const {return m_distributionParameterStSt;}

	/**
	 * Returns reference to Discrete Gaussian Generator for keys
	 *
	 * @return reference to Discrete Gaussian Generaror.
	 */
	const typename Element::DggType &GetDiscreteGaussianGeneratorStSt() const {return m_dggStSt;}

	//@Set Properties

	/**
	 * Sets the value of standard deviation r for discrete Gaussian distribution
	 */
	void SetDistributionParameterStSt(float distributionParameterStSt) {
		m_distributionParameterStSt = distributionParameterStSt;
		m_dggStSt.SetStd(m_distributionParameterStSt);
	}

	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @param fileFlag is an object-specific parameter for the serialization
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);
		if( this->SerializeRLWE(serObj, cryptoParamsMap) == false )
			return false;

		cryptoParamsMap.AddMember("DistributionParameterStSt", std::to_string(this->GetDistributionParameterStSt()), serObj->GetAllocator());

		serObj->AddMember("LPCryptoParametersStehleSteinfeld", cryptoParamsMap.Move(), serObj->GetAllocator());
		serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersStehleSteinfeld", serObj->GetAllocator());

		return true;
	}

	/**
	 * Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersStehleSteinfeld");
		if( mIter == serObj.MemberEnd() ) return false;

		if( this->DeserializeRLWE(mIter) == false )
			return false;

		SerialItem::ConstMemberIterator pIt;
		if( (pIt = mIter->value.FindMember("DistributionParameterStSt")) == mIter->value.MemberEnd() )
			return false;
		float distributionParameterStSt = atof(pIt->value.GetString());
		this->SetDistributionParameterStSt(distributionParameterStSt);
		return true;
	}


	bool operator==(const LPCryptoParameters<Element>& cmp) const {
		const LPCryptoParametersStehleSteinfeld<Element> *el = dynamic_cast<const LPCryptoParametersStehleSteinfeld<Element> *>(&cmp);

		if( el == 0 ) return false;

		return  LPCryptoParametersRLWE<Element>::operator==( cmp ) &&
				m_distributionParameterStSt == el->GetDistributionParameterStSt();
	}

private:
	//standard deviation in Discrete Gaussian Distribution used for Key Generation
	float m_distributionParameterStSt;
	//Discrete Gaussian Generator for Key Generation
	typename Element::DggType m_dggStSt;
};

/**
* @brief Encryption algorithm implementation template for Stehle-Stenfeld scheme,
* @tparam Element a ring element.
*/
template <class Element>
class LPEncryptionAlgorithmStehleSteinfeld : public LPAlgorithmLTV<Element> {
public:

	/**
	* Default constructor
	*/
	LPEncryptionAlgorithmStehleSteinfeld() : LPAlgorithmLTV<Element>() {};

	/**
	* Function to generate public and private keys
	*
	* @param &publicKey private key used for decryption.
	* @param &privateKey private key used for decryption.
	* @return function ran correctly.
	*/
	LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc, bool makeSparse=false) const { 		//makeSparse is not used

		LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));

		const shared_ptr<LPCryptoParametersStehleSteinfeld<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersStehleSteinfeld<Element>>(cc.GetCryptoParameters());

		const BigBinaryInteger &p = cryptoParams->GetPlaintextModulus();

		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGeneratorStSt();

		Element f(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);

		f = p*f;

		f = f + BigBinaryInteger::ONE;

		f.SwitchFormat();

		//check if inverse does not exist
		while (!f.InverseExists())
		{
			//std::cout << "inverse does not exist" << std::endl;
			Element temp(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);
			f = temp;
			f = p*f;
			f = f + BigBinaryInteger::ONE;
			f.SwitchFormat();
		}

		kp.secretKey->SetPrivateElement(f);

		Element g(dgg, cryptoParams->GetElementParams(), Format::COEFFICIENT);

		g.SwitchFormat();

		//public key is generated
		kp.publicKey->SetPublicElementAtIndex(0, cryptoParams->GetPlaintextModulus()*g*kp.secretKey->GetPrivateElement().MultiplicativeInverse());

		return kp;
	}
};

/**
* @brief Main public key encryption scheme for Stehle-Stenfeld scheme implementation,
* @tparam Element a ring element.
*/
template <class Element>
class LPPublicKeyEncryptionSchemeStehleSteinfeld : public LPPublicKeyEncryptionSchemeLTV<Element> {
public:
	/**
	* Inherited constructor
	*/
	LPPublicKeyEncryptionSchemeStehleSteinfeld() : LPPublicKeyEncryptionSchemeLTV<Element>() {}
	/**
	* Constructor that initalizes the mask
	*
	*@param mask the mask to be initialized
	*/
	LPPublicKeyEncryptionSchemeStehleSteinfeld(std::bitset<FEATURESETSIZE> mask) {
		if (mask[ENCRYPTION])
			this->m_algorithmEncryption = new LPEncryptionAlgorithmStehleSteinfeld<Element>();
		if (mask[PRE])
			this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>();
		if (mask[SHE])
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
	}

	/**
	* Function to enable a scheme
	*
	*@param feature is the feature to enable
	*/
	void Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPEncryptionAlgorithmStehleSteinfeld<Element>();
			break;
		case PRE:
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>();
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
			break;
		case SHE:
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>();
			break;
		}
	}
};


}

#endif
