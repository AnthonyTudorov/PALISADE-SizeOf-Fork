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

template<typename IntType> class ILParamsImpl;
typedef ILParamsImpl<BigBinaryInteger> ILParams;

}

namespace native64 {

typedef lbcrypto::ILParamsImpl<native64::BigBinaryInteger> ILParams;

}

namespace lbcrypto {

/**
 * @brief Parameters for ideal lattice: cyclotomic order and modulus.
 */
template<typename IntType>
class ILParamsImpl : public ElemParams<IntType>
{
public:

	/**
	 * Constructor that initializes nothing.
	 * All of the private members will be initialised to zero.
	 */
	ILParamsImpl()
		: ElemParams<IntType>(0,IntType::ZERO), m_rootOfUnity(IntType::ZERO) {}

	/**
	 * Constructor for the pre-computed case.
	 *
	 * @param &order the order of the ciphertext.
	 * @param &modulus the ciphertext modulus.
	 * @param &rootOfUnity the root of unity used in the ciphertext.
	 */
	ILParamsImpl(const usint order, const IntType & modulus, const IntType & rootOfUnity)
		: ElemParams<IntType>(order, modulus), m_rootOfUnity(rootOfUnity) {}

	/**
	 * Constructor for the pre-computed case.
	 *
	 * @param &order the order of the ciphertext.
	 * @param &modulus the ciphertext modulus.
	 */
	ILParamsImpl(const usint order, const IntType &modulus)
		: ElemParams<IntType>(order, modulus)
	{
		m_rootOfUnity = RootOfUnity<IntType>(order, modulus);
	}

	//copy constructor
	/**
	 * Copy constructor.
	 *
	 * @param &rhs the input set of parameters which is copied.
	 */
	ILParamsImpl(const ILParamsImpl &rhs) : ElemParams<IntType>(rhs), m_rootOfUnity(rhs.m_rootOfUnity) {}

	/**
	 * Assignment Operator.
	 *
	 * @param &rhs the ILParams to be copied.
	 * @return the resulting ILParams.
	 */
	const ILParamsImpl& operator=(const ILParamsImpl &rhs) {
		ElemParams<IntType>::operator=(rhs);
		return *this;
	}

	/**
	 * Move constructor.
	 *
	 * @param &rhs the input set of parameters which is copied.
	 */
	ILParamsImpl(const ILParamsImpl &&rhs) : ElemParams<IntType>(rhs) {}

	/**
	 * Destructor.
	 */
	virtual ~ILParamsImpl() {}

	// ACCESSORS

	// Get accessors

	/**
	 * Get the root of unity.
	 *
	 * @return the root of unity.
	 */
	const IntType &GetRootOfUnity() const {
		return m_rootOfUnity;
	}

	/**
	 * Equal operator compares ElemParams (which will be dynamic casted)
	 *
	 * @param &rhs is the specified ILVector2n to be compared with this ILVector2n.
	 * @return true if this ILVector2n represents the same values as the specified ILVectorArray2n, false otherwise
	 */
	bool operator==(const ElemParams<IntType>& rhs) const {
		if( dynamic_cast<const ILParamsImpl<IntType> *>(&rhs) == 0 )
			return false;

		return ElemParams<IntType>::operator==(rhs) && m_rootOfUnity == rhs.GetRootOfUnity();
	}

private:
	std::ostream& doprint(std::ostream& out) const {
		out << "ILParams ";
		ElemParams<IntType>::doprint(out);
		out << "Root of unity " << GetRootOfUnity();
		return out;
	}

public:
	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @param fileFlag is an object-specific parameter for the serialization
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const;

	/**
	 * Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj);

private:
	// primitive root unity that is used to transform from coefficient to evaluation representation and vice versa
	IntType m_rootOfUnity;

};


} // namespace lbcrypto ends

#endif
