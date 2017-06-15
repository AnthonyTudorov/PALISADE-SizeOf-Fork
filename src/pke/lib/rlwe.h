/**
 * @file rlwe.h -- PALISADE.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#ifndef LBCRYPTO_CRYPTO_RLWE_H
#define LBCRYPTO_CRYPTO_RLWE_H

#include "utils/serializable.h"
#include "lattice/ilvector2n.h"
#include <string>
#include "../../core/lib/lattice/ildcrt2n.h"

namespace lbcrypto {

/**
 * @brief Template for crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersRLWE : public LPCryptoParameters<Element> {
public:

	/**
	 * Default Constructor
	 */
	LPCryptoParametersRLWE() : LPCryptoParameters<Element>() {
		m_distributionParameter = 0.0f;
		m_assuranceMeasure = 0.0f;
		m_securityLevel = 0.0f;
		m_relinWindow = 1;
		m_dgg.SetStd(m_distributionParameter);
		m_depth = 0;
	}

	/**
	 * Copy constructor.
	 *
	 */
	LPCryptoParametersRLWE(const LPCryptoParametersRLWE &rhs) : LPCryptoParameters<Element>(rhs.GetElementParams(), rhs.GetPlaintextModulus()) {
		m_distributionParameter = rhs.m_distributionParameter;
		m_assuranceMeasure = rhs.m_assuranceMeasure;
		m_securityLevel = rhs.m_securityLevel;
		m_relinWindow = rhs.m_relinWindow;
		m_dgg.SetStd(m_distributionParameter);
		m_depth = rhs.m_depth;
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
	 * @param depth depth which defaults to 1.
	 */
	LPCryptoParametersRLWE(
			shared_ptr<typename Element::Params> params,
			const BigBinaryInteger &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			int depth = 1) : LPCryptoParameters<Element>(params, plaintextModulus)
					{
		m_distributionParameter = distributionParameter;
		m_assuranceMeasure = assuranceMeasure;
		m_securityLevel = securityLevel;
		m_relinWindow = relinWindow;
		m_dgg.SetStd(m_distributionParameter);
		m_depth = depth;
					}

	/**
	* Constructor that initializes values.
	*
	* @param &params element parameters.
	* @param &encodingParams encoding-specific parameters
	* @param distributionParameter noise distribution parameter.
	* @param assuranceMeasure assurance level.
	* @param securityLevel security level.
	* @param relinWindow the size of the relinearization window.
	* @param depth depth which defaults to 1.
	*/
	LPCryptoParametersRLWE(
		shared_ptr<typename Element::Params> params,
		shared_ptr<EncodingParams> encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		int depth = 1) : LPCryptoParameters<Element>(params, encodingParams)
	{
		m_distributionParameter = distributionParameter;
		m_assuranceMeasure = assuranceMeasure;
		m_securityLevel = securityLevel;
		m_relinWindow = relinWindow;
		m_dgg.SetStd(m_distributionParameter);
		m_depth = depth;
	}

	/**
	 * Destructor
	 */
	virtual ~LPCryptoParametersRLWE() {}

	/**
	 * Returns the value of standard deviation r for discrete Gaussian distribution
	 *
	 * @return the standard deviation r.
	 */
	float GetDistributionParameter() const { return m_distributionParameter; }

	/**
	 * Returns the values of assurance measure alpha
	 *
	 * @return the assurance measure.
	 */
	float GetAssuranceMeasure() const {return m_assuranceMeasure;}

	/**
	 * Returns the value of root Hermite factor security level /delta.
	 *
	 * @return the root Hermite factor /delta.
	 */
	float GetSecurityLevel() const {return m_securityLevel;}

	/**
	 * Returns the value of relinearization window.
	 *
	 * @return the relinearization window.
	 */
	usint GetRelinWindow() const { return m_relinWindow; }

	/**
	 * Returns the value of computation depth d
	 *
	 * @return the computation depth supported d.
	 */
	int GetDepth() const {return m_depth;}

	/**
	 * Returns reference to Discrete Gaussian Generator
	 *
	 * @return reference to Discrete Gaussian Generaror.
	 */
	const typename Element::DggType &GetDiscreteGaussianGenerator() const { return m_dgg; }

	//@Set Properties

	/**
	 * Sets the value of standard deviation r for discrete Gaussian distribution
	 * @param distributionParameter
	 */
	void SetDistributionParameter(float distributionParameter) {
		m_distributionParameter = distributionParameter;
		m_dgg.SetStd(m_distributionParameter);
	}

	/**
	 * Sets the values of assurance measure alpha
	 * @param assuranceMeasure
	 */
	void SetAssuranceMeasure(float assuranceMeasure) {m_assuranceMeasure = assuranceMeasure;}

	/**
	 * Sets the value of security level /delta
	 * @param securityLevel
	 */
	void SetSecurityLevel(float securityLevel) {m_securityLevel = securityLevel;}

	/**
	 * Sets the value of relinearization window
	 * @param relinWindow
	 */
	void SetRelinWindow(usint relinWindow) { m_relinWindow = relinWindow; }

	/**
	 * Sets the value of supported computation depth d
	 * @param depth
	 */
	void SetDepth(int depth) {m_depth = depth;}

	/**
	 * == operator to compare to this instance of LPCryptoParametersLTV object.
	 *
	 * @param &rhs LPCryptoParameters to check equality against.
	 */
	bool operator==(const LPCryptoParameters<Element> &rhs) const {
		const LPCryptoParametersRLWE<Element> *el = dynamic_cast<const LPCryptoParametersRLWE<Element> *>(&rhs);

		if( el == 0 ) return false;

		return this->GetPlaintextModulus() == el->GetPlaintextModulus() &&
				*this->GetElementParams() == *el->GetElementParams() &&
				*this->GetEncodingParams() == *el->GetEncodingParams() &&
				m_distributionParameter == el->GetDistributionParameter() &&
				m_assuranceMeasure == el->GetAssuranceMeasure() &&
				m_securityLevel == el->GetSecurityLevel() &&
				m_relinWindow == el->GetRelinWindow();
	}

	void PrintParameters(std::ostream& os) const {
		LPCryptoParameters<Element>::PrintParameters(os);

		os << "Distrib parm " << GetDistributionParameter() <<
				", Assurance measure " << GetAssuranceMeasure() <<
				", Security level " << GetSecurityLevel() <<
				", Relin window " << GetRelinWindow() <<
				", Depth " << GetDepth() << std::endl;
	}

protected:
	//standard deviation in Discrete Gaussian Distribution
	float m_distributionParameter;
	//assurance measure alpha
	float m_assuranceMeasure;
	//root Hermite value /delta
	float m_securityLevel;
	//relinearization window
	usint m_relinWindow;
	//depth of computations; used for FHE
	int m_depth;

	typename Element::DggType m_dgg;

	bool SerializeRLWE(Serialized* serObj, SerialItem& cryptoParamsMap) const {

		Serialized pser(rapidjson::kObjectType, &serObj->GetAllocator());

		if( !this->GetElementParams()->Serialize(&pser) )
			return false;

		Serialized encodingPser(rapidjson::kObjectType, &serObj->GetAllocator());

		if (!this->GetEncodingParams()->Serialize(&encodingPser))
			return false;

		cryptoParamsMap.AddMember("ElemParams", pser.Move(), serObj->GetAllocator());
		cryptoParamsMap.AddMember("EncodingParams", encodingPser.Move(), serObj->GetAllocator());
		cryptoParamsMap.AddMember("DistributionParameter", std::to_string(this->GetDistributionParameter()), serObj->GetAllocator());
		cryptoParamsMap.AddMember("AssuranceMeasure", std::to_string(this->GetAssuranceMeasure()), serObj->GetAllocator());
		cryptoParamsMap.AddMember("SecurityLevel", std::to_string(this->GetSecurityLevel()), serObj->GetAllocator());
		cryptoParamsMap.AddMember("RelinWindow", std::to_string(this->GetRelinWindow()), serObj->GetAllocator());
		cryptoParamsMap.AddMember("Depth", std::to_string(this->GetDepth()), serObj->GetAllocator());
		cryptoParamsMap.AddMember("PlaintextModulus", this->GetPlaintextModulus().ToString(), serObj->GetAllocator());

		return true;
	}

	bool DeserializeRLWE(Serialized::ConstMemberIterator mIter) {

		SerialItem::ConstMemberIterator pIt;

		if( (pIt = mIter->value.FindMember("ElemParams")) == mIter->value.MemberEnd() )
			return false;
		Serialized oneItem(rapidjson::kObjectType);
		SerialItem key( pIt->value.MemberBegin()->name, oneItem.GetAllocator() );
		SerialItem val( pIt->value.MemberBegin()->value, oneItem.GetAllocator() );
		oneItem.AddMember(key, val, oneItem.GetAllocator());

		typename Element::Params *json_ilParams = new typename Element::Params();

		if( !json_ilParams->Deserialize(oneItem) ) {
			delete json_ilParams;
			return false;
		}

		shared_ptr<typename Element::Params> ep( json_ilParams );
		this->SetElementParams( ep );

		SerialItem::ConstMemberIterator epIt;

		if ((epIt = mIter->value.FindMember("EncodingParams")) == mIter->value.MemberEnd())
			return false;
		Serialized oneItemE(rapidjson::kObjectType);
		SerialItem keyE(epIt->value.MemberBegin()->name, oneItemE.GetAllocator());
		SerialItem valE(epIt->value.MemberBegin()->value, oneItemE.GetAllocator());
		oneItemE.AddMember(keyE, valE, oneItemE.GetAllocator());

		EncodingParams *json_encodingParams = new EncodingParams();
		//		if( typeid(Element) == typeid(ILVector2n) )
		//			json_ilParams = new ILParams();
		//		else if( typeid(Element) == typeid(ILVectorArray2n) )
		//			json_ilParams = new ILDCRTParams();
		//		else {
		//			throw std::logic_error("Unrecognized element type");
		//		}

		if (!json_encodingParams->Deserialize(oneItemE)) {
			delete json_encodingParams;
			return false;
		}

		shared_ptr<EncodingParams> encodingParams(json_encodingParams);
		this->SetEncodingParams(encodingParams);

		if( (pIt = mIter->value.FindMember("PlaintextModulus")) == mIter->value.MemberEnd() )
			return false;
		BigBinaryInteger bbiPlaintextModulus(pIt->value.GetString());

		if( (pIt = mIter->value.FindMember("DistributionParameter")) == mIter->value.MemberEnd() )
			return false;
		float distributionParameter = atof(pIt->value.GetString());

		if( (pIt = mIter->value.FindMember("AssuranceMeasure")) == mIter->value.MemberEnd() )
			return false;
		float assuranceMeasure = atof(pIt->value.GetString());

		if( (pIt = mIter->value.FindMember("SecurityLevel")) == mIter->value.MemberEnd() )
			return false;
		float securityLevel = atof(pIt->value.GetString());

		if( (pIt = mIter->value.FindMember("RelinWindow")) == mIter->value.MemberEnd() )
			return false;
		usint relinWindow = atoi(pIt->value.GetString());

		if( (pIt = mIter->value.FindMember("Depth")) == mIter->value.MemberEnd() )
			return false;
		int depth = atoi(pIt->value.GetString());

		this->SetPlaintextModulus(bbiPlaintextModulus);
		this->SetDistributionParameter(distributionParameter);
		this->SetAssuranceMeasure(assuranceMeasure);
		this->SetSecurityLevel(securityLevel);
		this->SetRelinWindow(relinWindow);
		this->SetDepth(depth);

		return true;
	}
};
}

#endif
