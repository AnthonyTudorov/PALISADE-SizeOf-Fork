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

#ifndef LBCRYPTO_LATTICE_ELEMPARAMS_H
#define LBCRYPTO_LATTICE_ELEMPARAMS_H

#include "../utils/serializable.h"
#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"
#include <iostream>

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	/**
	* @brief Interface for element params; all these methods have to be supported by any element parameters class
	*/

	template <typename IntegerType>
	class ElemParams : public Serializable
	{
	public:
		ElemParams(usint order,
				const IntegerType& ctModulus = IntegerType::ZERO,
				const IntegerType& rUnity = IntegerType::ZERO,
				const IntegerType& bigCtModulus = IntegerType::ZERO,
				const IntegerType& bigRUnity = IntegerType::ZERO) {
			cyclotomicOrder = order;
			ringDimension = GetTotient(order);
			isPowerOfTwo = ringDimension == cyclotomicOrder / 2;
			ciphertextModulus = ctModulus;
			rootOfUnity = rUnity;
			bigCiphertextModulus = bigCtModulus;
			bigRootOfUnity = bigRUnity;
		}

		ElemParams(const ElemParams& rhs) {
			cyclotomicOrder = rhs.cyclotomicOrder;
			ringDimension = rhs.ringDimension;
			isPowerOfTwo = rhs.isPowerOfTwo;
			ciphertextModulus = rhs.ciphertextModulus;
			rootOfUnity = rhs.rootOfUnity;
			bigCiphertextModulus = rhs.bigCiphertextModulus;
			bigRootOfUnity = rhs.bigRootOfUnity;
		}

		ElemParams(const ElemParams&& rhs) {
			cyclotomicOrder = rhs.cyclotomicOrder;
			ringDimension = rhs.ringDimension;
			isPowerOfTwo = rhs.isPowerOfTwo;
			ciphertextModulus = std::move(rhs.ciphertextModulus);
			rootOfUnity = std::move(rhs.rootOfUnity);
			bigCiphertextModulus = std::move(rhs.bigCiphertextModulus);
			bigRootOfUnity = std::move(rhs.bigRootOfUnity);
		}

		const ElemParams& operator=(const ElemParams& rhs) {
			cyclotomicOrder = rhs.cyclotomicOrder;
			ringDimension = rhs.ringDimension;
			isPowerOfTwo = rhs.isPowerOfTwo;
			ciphertextModulus = rhs.ciphertextModulus;
			rootOfUnity = rhs.rootOfUnity;
			bigCiphertextModulus = rhs.bigCiphertextModulus;
			bigRootOfUnity = rhs.bigRootOfUnity;
			return *this;
		}

		virtual ~ElemParams() {}

		// GETTERS
		usint GetCyclotomicOrder() const { return cyclotomicOrder; }

		usint GetRingDimension() const { return ringDimension; }

		const bool OrderIsPowerOfTwo() const { return isPowerOfTwo; }

		const IntegerType &GetModulus() const { return ciphertextModulus; }
		const IntegerType &GetBigModulus() const { return bigCiphertextModulus; }
		const IntegerType &GetRootOfUnity() const { return rootOfUnity; }
		const IntegerType &GetBigRootOfUnity() const { return bigRootOfUnity; }

	    friend std::ostream& operator<<(std::ostream& out, const ElemParams &item) {
	    	return item.doprint(out);
	    }

		virtual bool operator==(const ElemParams<IntegerType> &other) const {
			return cyclotomicOrder == other.cyclotomicOrder &&
					ringDimension == other.ringDimension &&
					ciphertextModulus == other.ciphertextModulus &&
					rootOfUnity == other.rootOfUnity &&
					bigCiphertextModulus == other.bigCiphertextModulus &&
					bigRootOfUnity == other.bigRootOfUnity;
		}
		bool operator!=(const ElemParams<IntegerType> &other) const { return !(*this == other); }

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


	protected:
		usint			cyclotomicOrder;
		usint			ringDimension;
		bool			isPowerOfTwo;
		IntegerType		ciphertextModulus;
		IntegerType		rootOfUnity;
		IntegerType		bigCiphertextModulus;
		IntegerType		bigRootOfUnity;

		virtual std::ostream& doprint(std::ostream& out) const {
			out << "[m=" << cyclotomicOrder << (isPowerOfTwo?"* ":" ") << "n=" << ringDimension
					<< " q=" << ciphertextModulus
					<< " ru=" << rootOfUnity
					<< " bigq=" << bigCiphertextModulus
					<< " bigru=" << bigRootOfUnity
					<< "]";
			return out;
		}


	};

} // namespace lbcrypto ends

#endif
