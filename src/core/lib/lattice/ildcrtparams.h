/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>
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
 * LAYER 2 : LATTICE DATA STRUCTURES AND OPERATIONS
 * This code provides basic lattice ideal manipulation functionality.
 * For more information on ideal lattices please see here: 10.1007/978-3-540-88702-7_5
 * ILDCRTParmas stands for : Ideal Lattive Chinese Remainder Transform Params. This class provides a placeholder for the parameter set
 * of an ILVectorArray2n.
 *
 *  The private members of this class are:
 *
 *	 order of cyclotomic polynomial.
 *	 usint m_cyclotomicOrder;
 *
 *	// value of moduli
 *	 std::vector<BigBinaryInteger> m_moduli;
 *
 *	// primitive root unity that is used to transform from coefficient to evaluation representation and vice versa
 *	std::vector<BigBinaryInteger> m_rootsOfUnity;
 *
 *	//Modulus that is factorized into m_moduli
 *	BigBinaryInteger m_modulus;
 *
 */

#ifndef LBCRYPTO_LATTICE_ILDCRTELEMENT_H
#define LBCRYPTO_LATTICE_ILDCRTELEMENT_H

#include "../lattice/elemparams.h"
#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"
#include "../lattice/ilparams.h"

namespace lbcrypto {

template<typename ModType, typename IntType, typename VecType, typename ParmType> class ILVectorImpl;

}

namespace lbcrypto {

/**
 * @brief Parameters for array of ideal lattices (used for Double-CRT)
 */
template<typename IntType>
class ILDCRTParams : public ElemParams<IntType>
{
public:

	ILDCRTParams(usint order=0, usint depth=0, usint bits=0);

	/**
	 * Constructor with all parameters provided except the multiplied values of the chain of moduli. That value is automatically calculated. Root of unity of the modulus is also calculated.
	 *
	 * @param cyclotomic_order the order of the ciphertext
	 * @param &modulus is the modulus for the entire tower
	 * @param rootsOfUnity is unused
	 */
	ILDCRTParams(const usint cyclotomic_order, const BigBinaryInteger &modulus, const BigBinaryInteger& rootsOfUnity)
		: ElemParams<IntType>(cyclotomic_order, modulus) {}

	/**
	 * Constructor with all parameters provided except the multiplied values of the chain of moduli. That value is automatically calculated. Root of unity of the modulus is also calculated.
	 *
	 * @param rootsOfUnity the roots of unity for the chain of moduli
	 * @param cyclotomic_order the order of the ciphertext
	 * @param &moduli is the tower of moduli
	 */
	ILDCRTParams(const usint cyclotomic_order, const std::vector<native64::BigBinaryInteger> &moduli, const std::vector<native64::BigBinaryInteger>& rootsOfUnity)
		: ElemParams<IntType>(cyclotomic_order) {
		if( moduli.size() != rootsOfUnity.size() )
			throw std::logic_error("sizes of moduli and roots of unity do not match");

		for( int i=0; i<moduli.size(); i++ ) {
			m_parms.push_back( std::shared_ptr<native64::ILParams>( new native64::ILParams(cyclotomic_order, moduli[i], rootsOfUnity[i]) ) );
		}
		calculateModulus();
	}

	/**
	 * Constructor with only cylotomic order and chain of moduli. Multiplied values of the chain of moduli is automatically calculated. Root of unity of the modulus is also calculated.
	 *
	 * @param cyclotomic_order the order of the ciphertext
	 * @param &moduli is the tower of moduli
	 */
	ILDCRTParams(const usint cyclotomic_order, const std::vector<native64::BigBinaryInteger> &moduli)
		: ElemParams<IntType>(cyclotomic_order) {
		for( int i=0; i<moduli.size(); i++ ) {
			m_parms.push_back( std::shared_ptr<native64::ILParams>( new native64::ILParams(cyclotomic_order, moduli[i]) ) );
		}
		calculateModulus();
	}

	ILDCRTParams(const usint cyclotomic_order, std::vector<std::shared_ptr<native64::ILParams>>& parms)
		: ElemParams<IntType>(cyclotomic_order), m_parms(parms) {
		calculateModulus();
	}


//	/**
//	 * Assignment Operator.
//	 *
//	 * @param &rhs the copied ILDCRTParams.
//	 * @return the resulting ILDCRTParams.
//	 */
//	ILDCRTParams& operator=(const ILDCRTParams &rhs) {
//		this->m_cyclotomicOrder = rhs.m_cyclotomicOrder;
//		this->m_parms = rhs.m_parms;
//		this->m_modulus = rhs.m_modulus;
//
//		return *this;
//	}

	// ACCESSORS

	/**
	 * Get the root of unity.
	 *
	 * @return the root of unity.
	 */
	const IntType &GetRootOfUnity() const {
		throw std::logic_error("no single root of unity");
	}

	const std::vector<std::shared_ptr<native64::ILParams>> &GetParams() const {
		return m_parms;
	}

	std::shared_ptr<native64::ILParams>& operator[](const usint i) { return m_parms[i]; }

	/**
	 * Removes the last parameter set and adjust the multiplied moduli.
	 *
	 */
	void PopLastParam(){
		this->ciphertextModulus = this->ciphertextModulus / IntType(m_parms.back()->GetModulus().ConvertToInt());
		m_parms.pop_back();
	}

	/**
	 * Destructor.
	 */
	~ILDCRTParams() {}

	//JSON FACILITY
	bool Serialize(Serialized* serObj) const;

	bool Deserialize(const Serialized& serObj);

	/**
	 * == Operator checks if the ElemParams are the same.
	 *
	 * @param &other ElemParams to compare against.
	 * @return the equality check results.
	 */
	bool operator==(const ElemParams<IntType> &other) const {

		const ILDCRTParams *dcrtParams = dynamic_cast<const ILDCRTParams*>(&other);

		if( dcrtParams == 0 ) return 0;

		if( ElemParams<IntType>::operator==(other) == false )
			return false;

		if (m_parms.size() != dcrtParams->m_parms.size() )
			return false;

		for( int i=0; i < m_parms.size(); i++ ) {
			if( *m_parms[i] != *dcrtParams->m_parms[i] )
				return false;
		}

		return true;
	}

private:
	std::ostream& doprint(std::ostream& out) const {
		out << "ILDCRTParams ";
		ElemParams<IntType>::doprint(out);
		out << " Parms:" << std::endl;
		for( int i=0; i < m_parms.size(); i++ ) {
			out << "   " << i << ":" << *m_parms[i] << std::endl;
		}
		return out;
	}

private:
	// array of smaller ILParams
	std::vector<std::shared_ptr<native64::ILParams>>	m_parms;

	//This method 'pre-computes' the modulus based on the multiplication of moduli
	void calculateModulus(){

		this->ciphertextModulus = BigBinaryInteger(1);

		for(usint i = 0; i < m_parms.size(); i++) {
			this->ciphertextModulus = this->ciphertextModulus * BigBinaryInteger(m_parms[i]->GetModulus().ConvertToInt());
		}
	}


};

} // namespace lbcrypto ends

#endif
