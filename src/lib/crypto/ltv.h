/**0
 * @file ltv.h -- definitions for LTV Crypto Params
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

#ifndef LBCRYPTO_CRYPTO_LTV_H
#define LBCRYPTO_CRYPTO_LTV_H

#include "../crypto/rlwe.h"

namespace lbcrypto {

/**
 * @brief Template for crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersLTV: public LPCryptoParametersRLWE<Element> {
public:

	/**
	 * Constructor that initializes all values to 0.
	 */
	LPCryptoParametersLTV() : LPCryptoParametersRLWE<Element>() {}

	/**
	 * Copy constructor.
	 *
	 */
	LPCryptoParametersLTV(const LPCryptoParametersLTV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {}

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
	LPCryptoParametersLTV(
			shared_ptr<ElemParams> params,
			const BigBinaryInteger &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			int depth = 1)
	: LPCryptoParametersRLWE<Element>(
			params,
			plaintextModulus,
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {}

	/**
	 * Destructor
	 */
	virtual ~LPCryptoParametersLTV() {}

	//JSON FACILITY
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

		serObj->AddMember("LPCryptoParametersLTV", cryptoParamsMap.Move(), serObj->GetAllocator());
		serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersLTV", serObj->GetAllocator());

		return true;
	}

	/**
	 * Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersLTV");
		if( mIter == serObj.MemberEnd() ) return false;

		return this->DeserializeRLWE(mIter);
	}

	/**
	 * Creates a new set of parameters for LPCryptoParametersLTV amid a new ILDCRTParams. The new ILDCRTParams will allow for
	 * SHE operations of the existing depth. Note that the cyclotomic order also changes.
	 *
	 * @param *cryptoParams is where the resulting new LPCryptoParametersLTV will be placed in.
	 */
	template <class ILVectorArray2n>
	void ParameterSelection(LPCryptoParametersLTV<ILVectorArray2n> *cryptoParams) {

		//defining moduli outside of recursive call for efficiency
		std::vector<BigBinaryInteger> moduli(this->m_depth+1);
		moduli.reserve(this->m_depth+1);

		usint n = this->GetElementParams()->GetCyclotomicOrder()/2;
		// set the values for n (ring dimension) and chain of moduli
		this->ParameterSelection(n, moduli);

		cryptoParams->SetAssuranceMeasure(this->m_assuranceMeasure);
		cryptoParams->SetDepth(this->m_depth);
		cryptoParams->SetSecurityLevel(this->m_securityLevel);
		cryptoParams->SetDistributionParameter(this->m_distributionParameter);
		cryptoParams->SetPlaintextModulus(this->GetPlaintextModulus());

		std::vector<BigBinaryInteger> rootsOfUnity;
		rootsOfUnity.reserve(this->m_depth+1);
		usint m = n*2; //cyclotomic order
		BigBinaryInteger rootOfUnity;

		for(usint i = 0; i < this->m_depth+1; i++){
			rootOfUnity = RootOfUnity(m, moduli.at(i));
			rootsOfUnity.push_back(rootOfUnity);
		}

		shared_ptr<ElemParams> newElemParams( new ILDCRTParams(m, moduli, rootsOfUnity) );
		cryptoParams->SetElementParams(newElemParams);
	}

	/**
	 * == operator to compare to this instance of LPCryptoParametersLTV object.
	 *
	 * @param &rhs LPCryptoParameters to check equality against.
	 */
	bool operator==(const LPCryptoParameters<Element> &rhs) const {
		const LPCryptoParametersLTV<Element> *el = dynamic_cast<const LPCryptoParametersLTV<Element> *>(&rhs);

		if( el == 0 ) return false;
		return LPCryptoParametersRLWE<Element>::operator ==(rhs);
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
		int t = this->m_depth + 1;
		int d = this->m_depth;

		BigBinaryInteger pBigBinaryInteger(this->GetPlaintextModulus());
		int p = pBigBinaryInteger.ConvertToInt();
		double w = this->m_assuranceMeasure;
		double r = this->m_distributionParameter;
		double rootHermitFactor = this->m_securityLevel;

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
