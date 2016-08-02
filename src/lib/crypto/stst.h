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
 * This code provides the core proxy re-encryption functionality.
 */

#ifndef LBCRYPTO_CRYPTO_STST_H
#define LBCRYPTO_CRYPTO_STST_H

#include "rlwe.h"

namespace lbcrypto {
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
		m_dggStSt = DiscreteGaussianGenerator();
	}

	/**
	 * Copy constructor.
	 *
	 */
	LPCryptoParametersStehleSteinfeld(const LPCryptoParametersStehleSteinfeld &rhs) : LPCryptoParametersRLWE<Element>(rhs) {
		m_distributionParameterStSt = rhs.m_distributionParameterStSt;
		m_dggStSt = rhs.m_dggStSt;
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
	LPCryptoParametersStehleSteinfeld(ElemParams *params,
			const BigBinaryInteger &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			const DiscreteGaussianGenerator &dgg,
			const DiscreteGaussianGenerator &dggStSt,
			float distributionParmStst,
			int depth = 1)
	: LPCryptoParametersRLWE<Element>(params,
			plaintextModulus,
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			dgg,
			depth) {
		m_distributionParameterStSt = distributionParmStst;
		m_dggStSt = dggStSt;

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
	const DiscreteGaussianGenerator &GetDiscreteGaussianGeneratorStSt() const {return m_dggStSt;}

	//@Set Properties

	/**
	 * Sets the value of standard deviation r for discrete Gaussian distribution
	 */
	void SetDistributionParameterStSt(float distributionParameterStSt) {m_distributionParameterStSt = distributionParameterStSt;}

	/**
	 * Sets the discrete Gaussian Generator for keys
	 */
	void SetDiscreteGaussianGeneratorStSt(const DiscreteGaussianGenerator &dggStSt) {m_dggStSt = dggStSt;}

	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @param fileFlag is an object-specific parameter for the serialization
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj, const std::string fileFlag = "") const {
		if( !serObj->IsObject() )
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);
		if( this->SerializeRLWE(serObj, cryptoParamsMap, fileFlag) == false )
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


	bool operator==(const LPCryptoParameters<Element>* cmp) const {
		const LPCryptoParametersStehleSteinfeld<Element> *el = dynamic_cast<const LPCryptoParametersStehleSteinfeld<Element> *>(cmp);

		if( cmp == 0 ) return false;

		return  LPCryptoParametersRLWE<Element>::operator==( cmp ) &&
				m_distributionParameterStSt == el->GetDistributionParameterStSt();
	}

private:
	//standard deviation in Discrete Gaussian Distribution used for Key Generation
	float m_distributionParameterStSt;
	//Discrete Gaussian Generator for Key Generation
	DiscreteGaussianGenerator m_dggStSt;
};

}

#endif