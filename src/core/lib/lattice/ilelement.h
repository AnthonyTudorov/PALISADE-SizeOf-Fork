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

#ifndef LBCRYPTO_LATTICE_ILELEMENT_H
#define LBCRYPTO_LATTICE_ILELEMENT_H

#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	/**
	* @brief Interface for ideal lattices
	*/
	template <typename Element>
	class ILElement : public Serializable
	{
	public:
		virtual ~ILElement() {}

		/**
		*Prints all values in either coefficient or evaluation format.
		*/		
		virtual void PrintValues() const = 0;
		
		/**
		*	Adds one to every entry on the ILElement.
		*/
		virtual void AddILElementOne() = 0;
		
		/**
		 * GetLength of the Element
		 * @return length
		 */
		virtual usint GetLength() const = 0;

		virtual const BigBinaryInteger& GetModulus() const = 0;
		virtual const BigBinaryVector& GetValues() const = 0;

		/**
		* ModReduce reduces the ILVectorArray2n's composite modulus by dropping the last modulus from the chain of moduli as well as dropping the last tower.
		*
		*@param plaintextModulus is the plaintextModulus used for the ILVectorArray2n
		*/
		virtual void ModReduce(const BigBinaryInteger &plaintextModulus) {
			throw std::logic_error("ModReduce is not implemented");
		}


		/**
		* Virtual interface for interpolation based on the Chinese Remainder Transform Interpolation.
		*
		* @return the original ring element.
		*/
		virtual Element CRTInterpolate() const = 0;

	};

} // namespace lbcrypto ends

#endif
