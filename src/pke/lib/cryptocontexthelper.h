/**
* @file
* @author	TPOC:
				Dr. Kurt Rohloff <rohloff@njit.edu>,
			Programmers:
				Jerry Ryan <gwryan@njit.edu>

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
* This file defines a helper class for managing and manipulating Crypto Contexts
*/

#ifndef SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_
#define SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_

#include <string>
#include <iostream>

#include "utils/serializablehelper.h"
#include "cryptocontext.h"
#include "cryptocontextparametersets.h"

namespace lbcrypto {

class CryptoContextHelper {
public:

	/**
	 *
	 * @param out stream to write to
	 */
	static void printAllParmSets(std::ostream& out);

	/**
	 *
	 * @param out stream to write to
	 * @param parmset parameter set name
	 */
	static void printParmSet(std::ostream& out, string parmset);

	/**
	 *
	 * @param out stream to write to
	 */
	static void printAllParmSetNames(std::ostream& out);

	/**
	 * Generate a CryptoContext for a given parameter set name
	 *
	 * @param parmsetname name of parameter set to use
	 * @return newly constructed CryptoContext, or null on failure
	 */
	static CryptoContext<ILVector2n> getNewContext(const string& parmsetname);

	/**
	 * Generate a DCRT CryptoContext for a given parameter set name
	 *
	 * @param parmsetname name of parameter set to use
	 * @param numTowers - how many towers to generate
	 * @param primeBits - bit width of the primes in the towers
	 * @return newly constructed CryptoContext, or null on failure
	 */
	static CryptoContext<ILVectorArray2n> getNewDCRTContext(const string& parmsetname, usint numTowers, usint primeBits);

	static bool matchContextToSerialization(const CryptoContext<ILVector2n> cc, const Serialized& ser);
	static bool matchContextToSerialization(const CryptoContext<ILVectorArray2n> cc, const Serialized& ser);
};

}

#endif /* SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_ */
