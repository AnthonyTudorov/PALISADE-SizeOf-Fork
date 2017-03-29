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

#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"
#include "../utils/serializable.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ilvector2n.h"

namespace lbcrypto {

template<typename ModType, typename IntType, typename VecType, typename ParmType> class ILVectorImpl;

}

//namespace native64 {
//
//typedef lbcrypto::DiscreteGaussianGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector> DiscreteGaussianGenerator;
//typedef lbcrypto::DiscreteUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector> DiscreteUniformGenerator;
//
//}

namespace lbcrypto {

/**
 * @brief Parameters for array of ideal lattices (used for Double-CRT)
 */
class ILDCRTParams : public ElemParams<BigBinaryInteger>
{
public:

	/**
	 * Constructor that initializes nothing.
	 */
	ILDCRTParams(usint depth = 0) : m_cyclotomicOrder(0) {
		m_parms.resize(depth);
	}

	ILDCRTParams(usint order, usint depth) {
		m_cyclotomicOrder = order;
		m_parms.resize(depth);

		native64::BigBinaryInteger q("50000");
		native64::BigBinaryInteger temp;
		BigBinaryInteger modulus(BigBinaryInteger::ONE);

		native64::BigBinaryInteger mod, root;

		for (int j = 0; j < depth; j++) {
			lbcrypto::NextQ<native64::BigBinaryInteger>(q, native64::BigBinaryInteger::FIVE, order, native64::BigBinaryInteger::FOUR, native64::BigBinaryInteger::FOUR);
			mod = q;
			root = RootOfUnity<native64::BigBinaryInteger>(order, mod);

			std::shared_ptr<native64::ILParams> p( new native64::ILParams(order, mod, root) );
			m_parms[j] = p;
			modulus = modulus * BigBinaryInteger(mod.ConvertToInt());
		}

		this->m_modulus = modulus;
	}

	/**
	 * Constructor with all parameters provided except the multiplied values of the chain of moduli. That value is automatically calculated. Root of unity of the modulus is also calculated.
	 *
	 * @param cyclotomic_order the order of the ciphertext
	 * @param &modulus is the modulus for the entire tower
	 * @param rootsOfUnity is unused
	 */
	ILDCRTParams(const usint cyclotomic_order, const BigBinaryInteger &modulus, const BigBinaryInteger& rootsOfUnity) {
		m_cyclotomicOrder = cyclotomic_order;
		m_modulus = modulus;
	}

	/**
	 * Constructor with all parameters provided except the multiplied values of the chain of moduli. That value is automatically calculated. Root of unity of the modulus is also calculated.
	 *
	 * @param rootsOfUnity the roots of unity for the chain of moduli
	 * @param cyclotomic_order the order of the ciphertext
	 * @param &moduli is the tower of moduli
	 */
	ILDCRTParams(const usint cyclotomic_order, const std::vector<native64::BigBinaryInteger> &moduli, const std::vector<native64::BigBinaryInteger>& rootsOfUnity) {
		if( moduli.size() != rootsOfUnity.size() )
			throw std::logic_error("sizes of moduli and roots of unity do not match");
		m_cyclotomicOrder = cyclotomic_order;
		m_modulus = BigBinaryInteger::ONE;
		for( int i=0; i<moduli.size(); i++ ) {
			m_parms.push_back( shared_ptr<native64::ILParams>( new native64::ILParams(cyclotomic_order, moduli[i], rootsOfUnity[i]) ) );
		}
		calculateModulus();
	}

	/**
	 * Constructor with only cylotomic order and chain of moduli. Multiplied values of the chain of moduli is automatically calculated. Root of unity of the modulus is also calculated.
	 *
	 * @param cyclotomic_order the order of the ciphertext
	 * @param &moduli is the tower of moduli
	 */
	ILDCRTParams(const usint cyclotomic_order, const std::vector<native64::BigBinaryInteger> &moduli) {
		m_cyclotomicOrder = cyclotomic_order;
		for( int i=0; i<moduli.size(); i++ ) {
			m_parms.push_back( shared_ptr<native64::ILParams>( new native64::ILParams(cyclotomic_order, moduli[i]) ) );
		}
		calculateModulus();
	}

	/**
	 * Assignment Operator.
	 *
	 * @param &rhs the copied ILDCRTParams.
	 * @return the resulting ILDCRTParams.
	 */
	ILDCRTParams& operator=(const ILDCRTParams &rhs) {
		this->m_cyclotomicOrder = rhs.m_cyclotomicOrder;
		this->m_parms = rhs.m_parms;
		this->m_modulus = rhs.m_modulus;

		return *this;
	}

	// ACCESSORS

	// Get accessors
	/**
	 * Get method of the order.
	 *
	 * @return the cyclotmic order.
	 */
	const usint GetCyclotomicOrder() const {
		return m_cyclotomicOrder;
	}

	/**
	 * Get modulus.
	 *
	 * @return the modulus.
	 */
	const BigBinaryInteger &GetModulus() const {
		return m_modulus;
	}

	/**
	 * Get the root of unity.
	 *
	 * @return the root of unity.
	 */
	const BigBinaryInteger &GetRootOfUnity() const {
		throw std::logic_error("no single root of unity");
	}

	const std::vector<std::shared_ptr<native64::ILParams>> &GetParams() const {
		return m_parms;
	}

	std::shared_ptr<native64::ILParams>& operator[](const usint i) { return m_parms[i]; }

	/**
	 * Set method of the order.
	 *
	 * @param order the order variable.
	 */
	void SetCyclotomicOrder(const usint order) {
		m_cyclotomicOrder = order;
	}

	/**
	 * Set the modulus.
	 *
	 * @param &modulus modulus value of the multiplied value of the chain of moduli.
	 */
	void SetModulus(const BigBinaryInteger &modulus) {
		m_modulus = modulus;
	}

	/**
	 * Removes the last parameter set and adjust the multiplied moduli.
	 *
	 */
	void PopLastParam(){
		m_modulus = m_modulus / BigBinaryInteger(m_parms.back()->GetModulus().ConvertToInt());
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
	bool operator==(const ElemParams &other) const {

		const ILDCRTParams *dcrtParams = dynamic_cast<const ILDCRTParams*>(&other);

		if( dcrtParams == 0 ) return 0;

		if (m_modulus != dcrtParams->GetModulus()) {
			return false;
		}
		if (m_cyclotomicOrder != dcrtParams->GetCyclotomicOrder()) {
			return false;
		}

		if (m_parms.size() != dcrtParams->m_parms.size() )
			return false;

		for( int i=0; i < m_parms.size(); i++ ) {
			if( m_parms[i] != dcrtParams->m_parms[i] )
				return false;
		}

		return true;
	}

private:
	std::ostream& doprint(std::ostream& out) const {
		out << "ILDCRTParams: mod " << GetModulus() << " order " << GetCyclotomicOrder() << std::endl;
		out << "Parms:" << std::endl;
		for( int i=0; i < m_parms.size(); i++ ) {
			out << "   " << i << ": modulus=" << m_parms[i]->GetModulus() << " root of unity=" << m_parms[i]->GetRootOfUnity() << std::endl;
		}
		return out;
	}

private:
	// order of cyclotomic polynomial
	usint m_cyclotomicOrder;

	// array of smaller ILParams
	std::vector<std::shared_ptr<native64::ILParams>>	m_parms;

	//Modulus that is factorized into m_moduli
	BigBinaryInteger m_modulus;

	//This method 'pre-computes' the modulus based on the multiplication of moduli
	void calculateModulus(){

		m_modulus = BigBinaryInteger(1);

		for(usint i = 0; i < m_parms.size(); i++){
			m_modulus = m_modulus * BigBinaryInteger(m_parms[i]->GetModulus().ConvertToInt());
		}
	}


};

} // namespace lbcrypto ends

#endif
