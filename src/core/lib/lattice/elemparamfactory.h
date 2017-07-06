/**
 * @file elemparamfactory.h Creates ElemParams objects for PALISADE.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#ifndef SRC_CORE_LIB_LATTICE_ELEMPARAMFACTORY_H_
#define SRC_CORE_LIB_LATTICE_ELEMPARAMFACTORY_H_

#include <memory>
using std::shared_ptr;

#include "../math/backend.h"
#include "ilparams.h"
#include "ildcrtparams.h"

namespace lbcrypto {

// predefined values of m are 16, 1024, 2048, 4096, 8192, 16384, 32768 and 65536

enum ElementOrder {
	M16 = 0,
	M1024,
	M2048,
	M4096,
	M8192,
	M16384,
	M32768
};

class ElemParamFactory {
public:
	static struct ElemParmSet {
		usint				m;	// cyclotomic order
		usint				n;	// ring dimension
		BigBinaryInteger	q;	// ciphertext modulus
		BigBinaryInteger	ru;	// root of unity
	} DefaultSet[];

	static shared_ptr<ILParams> GenElemParams(ElementOrder o) {
		return shared_ptr<ILParams>( new ILParams(DefaultSet[o].m, DefaultSet[o].q, DefaultSet[o].ru) );
	}
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_LATTICE_ELEMPARAMFACTORY_H_ */
