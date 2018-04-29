/**
 * @file circuitinput.h -- Representation of objects into and out of a circuit
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * This code provides support for input and output of a circuit
 *
 */

#include "circuitvalue.h"

namespace lbcrypto {

// actual operations performed, based on types
template<typename Element>
map<OpKey,OpValue> CircuitValue<Element>::operations = {
		{ OpKey(OpEvalAdd,CIPHERTEXT,CIPHERTEXT), OpValue(CIPHERTEXT,OpEvalAdd) },
		{ OpKey(OpEvalAdd,PLAINTEXT,CIPHERTEXT), OpValue(CIPHERTEXT,OpEvalAddPlain) },
		{ OpKey(OpEvalAdd,CIPHERTEXT,PLAINTEXT), OpValue(CIPHERTEXT,OpEvalAddPlain) },
		{ OpKey(OpEvalAdd,MATRIX_RAT,MATRIX_RAT), OpValue(MATRIX_RAT,OpEvalAddMatrix) },

		{ OpKey(OpEvalNeg,CIPHERTEXT), OpValue(CIPHERTEXT,OpEvalNeg) },
		{ OpKey(OpEvalNeg,MATRIX_RAT), OpValue(MATRIX_RAT,OpEvalNegMatrix) },

		{ OpKey(OpModReduce,CIPHERTEXT), OpValue(CIPHERTEXT,OpModReduce) },
		{ OpKey(OpModReduce,MATRIX_RAT), OpValue(MATRIX_RAT,OpModReduceMatrix) },

		{ OpKey(OpEvalMult,CIPHERTEXT,CIPHERTEXT), OpValue(CIPHERTEXT,OpEvalMult) },
		{ OpKey(OpEvalMult,PLAINTEXT,CIPHERTEXT), OpValue(CIPHERTEXT,OpEvalMultPlain) },
		{ OpKey(OpEvalMult,CIPHERTEXT,PLAINTEXT), OpValue(CIPHERTEXT,OpEvalMultPlain) },
		{ OpKey(OpEvalMult,MATRIX_RAT,MATRIX_RAT), OpValue(MATRIX_RAT,OpEvalMultMatrix) },

};

}
