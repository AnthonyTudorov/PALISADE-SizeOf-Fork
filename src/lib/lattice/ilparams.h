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
 */

#ifndef LBCRYPTO_LATTICE_ILPARAMS_H
#define LBCRYPTO_LATTICE_ILPARAMS_H

#include "elemparams.h"
#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

// Parameters for ideal lattice: cyclotomic order and modulus
/**
 * @brief Parameters for ideal lattice: cyclotomic order and modulus.
 */
class ILParams : public ElemParams
{
public:

	/**
	 * Constructor that initializes nothing.
	 * All of the private members will be initialised to zero.
	 */
	ILParams(): m_modulus(0), m_order(0), m_rootOfUnity(0) {
	}//no need of writing this as all of the private members will be initialised to zero

	// constructor for the pre-computed case;
	/**
	 * Constructor for the pre-computed case.
	 *
	 * @param &order the order of the ciphertext.
	 * @param &modulus the ciphertext modulus.
	 * @param &rootOfUnity the root of unity used in the ciphertext.
	 */
	ILParams(const usint order, const BigBinaryInteger & modulus, const BigBinaryInteger & rootOfUnity) {
		m_order = order;
		m_modulus = modulus;
		m_rootOfUnity = rootOfUnity;
	}

	/**
	 * Constructor for the pre-computed case.
	 *
	 * @param &order the order of the ciphertext.
	 * @param &modulus the ciphertext modulus.
	 */
	ILParams(const usint order, const BigBinaryInteger &modulus) {
		m_order = order;
		m_modulus = modulus;
		m_rootOfUnity = RootOfUnity(order, modulus);
	}

	//copy constructor
	/**
	 * Copy constructor.
	 *
	 * @param &rhs the input set of parameters which is copied.
	 */
	ILParams(const ILParams &rhs) {
		m_order = rhs.m_order;
		m_modulus = rhs.m_modulus;
		m_rootOfUnity = rhs.m_rootOfUnity;
	}

	/**
	 * Assignment Operator.
	 *
	 * @param &rhs the ILParams to be copied.
	 * @return the resulting ILParams.
	 */
	ILParams& operator=(const ILParams &) = default;

	/**
	 * Move constructor.
	 *
	 * @param &rhs the input set of parameters which is copied.
	 */
	ILParams(const ILParams &&rhs) {
		m_order = rhs.m_order;
		m_modulus = std::move(rhs.m_modulus);
		m_rootOfUnity = std::move(rhs.m_rootOfUnity);
	}

	/**
	 * Destructor.
	 */
	virtual ~ILParams() {
	}

	/**
	 * Initialize the values - used with default constructor; the values are computed
	 *
	 * @param m the cyclotimic order.
	 * @param bitLength minimum bit length for ciphertext modulus.
	 */
	virtual bool Initialize(usint m, usint bitLength) {
		//add a code that selects a modulus and computes a root of unity
		return false;
	}

	/**
	 * Initialize the values - used with default constructor; the values are imported from a pre-computed taxt file.
	 *
	 * @param m the cyclotimic order.
	 * @param bitLength minimum bit length for ciphertext modulus.
	 * @param &inputFile the full path to the text file containing the ciphertext modulues and root of unity for a given set of m and bitLength
	 */
	virtual bool Initialize(usint m, usint bitLength, const std::string &inputFile) {
		//add a code that sets all parameters using an entry in the text file with pre-computed values
		return false;
	}

	// ACCESSORS

	// Get accessors
	/**
	 * Get method of the order.
	 *
	 * @return the order.
	 */
	const usint GetCyclotomicOrder() const {
		return m_order;
	}

	/**
	 * Get the modulus.
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
		return m_rootOfUnity;
	}

	// Set accessors
	/**
	 * Set method of the order.
	 *
	 * @param order the order variable.
	 */
	void SetCyclotomicOrder(usint order) {
		m_order = order;
	}

	/**
	 * Set the root of unity.
	 *
	 * @param &rootOfUnity the root of unity.
	 */
	void SetRootOfUnity(const BigBinaryInteger &rootOfUnity) {
		m_rootOfUnity = rootOfUnity;
	}

	/**
	 * Set the modulus.
	 *
	 * @param &modulus the modulus.
	 */
	void SetModulus(const BigBinaryInteger &modulus) {
		m_modulus = modulus;
	}
	/**
	 * Equal operator compares this ILVector2n to the specified ElemParams (which will be dynamic casted)
	 *
	 * @param &rhs is the specified ILVector2n to be compared with this ILVector2n.
	 * @return true if this ILVector2n represents the same values as the specified ILVectorArray2n, false otherwise
	 */
	bool operator==(const ElemParams& rhs) const {
		const ILParams *ip = dynamic_cast<const ILParams *>(&rhs);

		if( ip == 0 )
			return false;

		if (m_modulus != ip->GetModulus()) {
			return false;
		}
		if (m_order != ip->GetCyclotomicOrder()) {
			return false;
		}
		if (m_rootOfUnity != ip->GetRootOfUnity()) {
			return false;
		}
		return true;
	}

	/**
	 * Not equal operator compares this ILParams to the specified ILParams
	 *
	 * @param &rhs is the specified ILParams to be compared with this ILParams.
	 * @return true if this ILParams represents the same values as the specified ILParams, false otherwise
	 */
	inline bool operator!=(ILParams const &rhs) {
		return !(*this == rhs);
	}

	std::ostream& operator<<(std::ostream& out, const ElemParams &item) {
		const ILParams *ip = dynamic_cast<const ILParams *>(&item);

		if( ip == 0 ) {
			out << "*** arg not ILParams" << std::endl;
		} else {
			out << "ILParams: mod " << ip->GetModulus() << " order " << ip->GetCyclotomicOrder() << " root of unity " << ip->GetRootOfUnity() << std::endl;
		}
		return out;
	}

	//JSON FACILITY
	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @param fileFlag is an object-specific parameter for the serialization
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj, const std::string fileFlag = "") const;

	/**
	 * Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj);

private:
	// order of cyclotomic polynomial
	usint m_order;

	// value of modulus
	BigBinaryInteger m_modulus;

	// primitive root unity that is used to transform from coefficient to evaluation representation and vice versa
	BigBinaryInteger m_rootOfUnity;

};


} // namespace lbcrypto ends

#endif
