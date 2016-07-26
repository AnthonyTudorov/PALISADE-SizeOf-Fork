/**0
 * @file
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
 * Base class for all RLWE-based Crypto Parameters
 */

#ifndef LBCRYPTO_CRYPTO_RLWE_H
#define LBCRYPTO_CRYPTO_RLWE_H

#include "../utils/serializable.h"
#include <string>

namespace lbcrypto {

/**
 * @brief Template for crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersRLWE : public LPCryptoParametersImpl<Element> {
public:

	/**
	 * Constructor that initializes all values to 0.
	 */
	LPCryptoParametersRLWE() : LPCryptoParametersImpl<Element>() {
		m_distributionParameter = 0.0f;
		m_assuranceMeasure = 0.0f;
		m_securityLevel = 0.0f;
		m_relinWindow = 1;
		m_dgg = DiscreteGaussianGenerator();
		m_depth = 0;
	}

	/**
	 * Copy constructor.
	 *
	 */
	LPCryptoParametersRLWE(const LPCryptoParametersRLWE &rhs) : LPCryptoParametersImpl<Element>(NULL, rhs.GetPlaintextModulus()) {

		m_distributionParameter = rhs.m_distributionParameter;
		m_assuranceMeasure = rhs.m_assuranceMeasure;
		m_securityLevel = rhs.m_securityLevel;
		m_relinWindow = rhs.m_relinWindow;
		m_dgg = rhs.m_dgg;
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
	LPCryptoParametersRLWE(ElemParams *params,
			const BigBinaryInteger &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			const DiscreteGaussianGenerator &dgg,
			int depth = 1) : LPCryptoParametersImpl<Element>(params,plaintextModulus)
					{
		m_distributionParameter = distributionParameter;
		m_assuranceMeasure = assuranceMeasure;
		m_securityLevel = securityLevel;
		m_relinWindow = relinWindow;
		m_dgg = dgg;
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
	float GetDistributionParameter() const {return m_distributionParameter;}

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
	const DiscreteGaussianGenerator &GetDiscreteGaussianGenerator() const {return m_dgg;}

	//@Set Properties

	/**
	 * Sets the value of standard deviation r for discrete Gaussian distribution
	 */
	void SetDistributionParameter(float distributionParameter) {m_distributionParameter = distributionParameter;}

	/**
	 * Sets the values of assurance measure alpha
	 */
	void SetAssuranceMeasure(float assuranceMeasure) {m_assuranceMeasure = assuranceMeasure;}

	/**
	 * Sets the value of security level /delta
	 */
	void SetSecurityLevel(float securityLevel) {m_securityLevel = securityLevel;}

	/**
	 * Sets the value of relinearization window
	 */
	void SetRelinWindow(usint relinWindow) { m_relinWindow = relinWindow; }

	/**
	 * Sets the value of supported computation depth d
	 */
	void SetDepth(int depth) {m_depth = depth;}

	/**
	 * Sets the discrete Gaussian Generator
	 */
	void SetDiscreteGaussianGenerator(const DiscreteGaussianGenerator &dgg) {m_dgg = dgg;}

	/**
	 * Creates a new set of parameters for LPCryptoParametersLTV amid a new ILDCRTParams. The new ILDCRTParams will allow for
	 * SHE operations of the existing depth. Note that the cyclotomic order also changes.
	 *
	 * @param *cryptoParams is where the resulting new LPCryptoParametersLTV will be placed in.
	 */
	template <class ILVectorArray2n>
	void ParameterSelection(LPCryptoParametersLTV<ILVectorArray2n> *cryptoParams) {

		//defining moduli outside of recursive call for efficiency
		std::vector<BigBinaryInteger> moduli(m_depth+1);
		moduli.reserve(m_depth+1);

		usint n = this->GetElementParams().GetCyclotomicOrder()/2;
		// set the values for n (ring dimension) and chain of moduli
		this->ParameterSelection(n, moduli);

		cryptoParams->SetAssuranceMeasure(m_assuranceMeasure);
		cryptoParams->SetDepth(m_depth);
		cryptoParams->SetSecurityLevel(m_securityLevel);
		cryptoParams->SetDistributionParameter(m_distributionParameter);
		cryptoParams->SetDiscreteGaussianGenerator(m_dgg);
		cryptoParams->SetPlaintextModulus(this->GetPlaintextModulus());

		std::vector<BigBinaryInteger> rootsOfUnity;
		rootsOfUnity.reserve(m_depth+1);
		usint m = n*2; //cyclotomic order
		BigBinaryInteger rootOfUnity;

		for(usint i = 0; i < m_depth+1; i++){
			rootOfUnity = RootOfUnity(m, moduli.at(i));
			rootsOfUnity.push_back(rootOfUnity);
		}

		ILDCRTParams *newCryptoParams = new ILDCRTParams(m, moduli, rootsOfUnity);
		cryptoParams->SetElementParams(*newCryptoParams);
	}

	/**
	 * == operator to compare to this instance of LPCryptoParametersLTV object.
	 *
	 * @param &rhs LPCryptoParameters to check equality against.
	 */
	virtual bool operator==(const LPCryptoParameters<Element> &rhs) const {
		const LPCryptoParametersRLWE<Element> *el = dynamic_cast<const LPCryptoParametersRLWE<Element> *>(&rhs);

		if( el == 0 ) return false;

		return  this->GetPlaintextModulus() == el->GetPlaintextModulus() &&
				this->GetElementParams() == el->GetElementParams() &&
				m_distributionParameter == el->GetDistributionParameter() &&
				m_assuranceMeasure == el->GetAssuranceMeasure() &&
				m_securityLevel == el->GetSecurityLevel() &&
				m_relinWindow == el->GetRelinWindow();
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
	//Discrete Gaussian Generator
	DiscreteGaussianGenerator m_dgg;

	bool SerializeRLWE(Serialized* serObj, SerialItem& cryptoParamsMap, const std::string fileFlag) const {

		Serialized pser(rapidjson::kObjectType);
		const ElemParams& ep = this->GetElementParams();
		if( !ep.Serialize(&pser, fileFlag) )
			return false;

		cryptoParamsMap.AddMember("ElemParams", pser.Move(), serObj->GetAllocator());
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

		ElemParams *json_ilParams = new ILParams();
		if( !json_ilParams->Deserialize(oneItem) ) {
			delete json_ilParams;
			return false;
		}

		this->SetElementParams(*json_ilParams);

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

private:
	//helper function for ParameterSelection. Splits the string 's' by the delimeter 'c'.
	std::string split(const std::string s, char c){
		std::string result;
		const char *str = s.c_str();
		const char *begin = str;
		while(*str != c && *str)
			str++;
		result = std::string(begin, str);
		return result;
	}

	//function for parameter selection. The public ParameterSelection function is a wrapper around this function.
	void ParameterSelection(usint& n, vector<BigBinaryInteger> &moduli) {
		int t = m_depth + 1;
		int d = m_depth;

		BigBinaryInteger pBigBinaryInteger(this->GetPlaintextModulus());
		int p = pBigBinaryInteger.ConvertToInt();
		double w = m_assuranceMeasure;
		double r = m_distributionParameter;
		double rootHermitFactor = m_securityLevel;

		double sqrtn = sqrt(n);
		double q1 = 4 * p * r * sqrtn * w;
		double q2 = 4 * pow(p, 2) * pow(r, 5) * pow(sqrtn, 3) * pow(w, 5);

		BigBinaryInteger plaintextModulus(p);

		double* q = new double[t];
		q[0] = q1;
		for(int i=1; i<t; i++)
			q[i] = q2;

		double sum = 0.0;
		for(int i=0; i<t; i++) {
			sum += log(q[i]);
		}

		int next = ceil(sum/ (4 * log(rootHermitFactor)));
		int nprime = pow(2, ceil(log(next)/log(2)));
		char c = '.';

		if(n == nprime) {
			sum = 0.0;
			for(int i=0; i<t; i++) {
				moduli[i] = BigBinaryInteger(split(std::to_string(q[i]), c));
				if(i == 0 || i == 1){
					NextQ(moduli[i], pBigBinaryInteger, n, BigBinaryInteger("4"), BigBinaryInteger("4"));
				}
				else{
					moduli[i] = moduli[i-1];
					NextQ(moduli[i], pBigBinaryInteger, n, BigBinaryInteger("4"), BigBinaryInteger("4"));
				}
				q[i] = moduli[i].ConvertToDouble();
				sum += log(q[i]);
			}

			int nprimeCalcFactor = ceil(sum/ (4 * log(rootHermitFactor)));
			if(nprime < nprimeCalcFactor){
				n *= 2;
				ParameterSelection(n, moduli);
			}
		} else {
			n *= 2;
			ParameterSelection(n, moduli);
		}

		delete q;
	}

};
}

#endif
