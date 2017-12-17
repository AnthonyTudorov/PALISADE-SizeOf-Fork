/**
 * @file testcasegen.h Helper methods for serialization.
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

#ifndef SRC_CORE_LIB_UTILS_TESTCASEGEN_H_
#define SRC_CORE_LIB_UTILS_TESTCASEGEN_H_

#define GENERATE_PKE_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, PTM) \
		TEST_F(TOPNAME, FUNC ## _ ## ELEMENT ## _ ## SCHEME ) { \
	CryptoContext<ELEMENT> cc; \
	try { \
		cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, PTM); \
	} catch( ... ) { \
		return; \
	} \
	FUNC<ELEMENT>(cc, #SCHEME); \
}

#define GENERATE_PKE_TEST_CASE_BITS(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, PTM, BITS) \
		TEST_F(TOPNAME, FUNC ## _ ## ELEMENT ## _ ## SCHEME ) { \
	CryptoContext<ELEMENT> cc; \
	try { \
		cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, PTM, BITS); \
	} catch( ... ) { \
		return; \
	} \
	FUNC<ELEMENT>(cc, #SCHEME); \
}

// Somebody should figure out how to do recursive macros. I give up. For now.

//#define _PP_0(_1, ...) _1
//#define _PP_X(_1, ...) (__VA_ARGS__)

//#define ITER_0(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[0])
//#define ITER_1(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_0(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[1])
//#define ITER_2(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_1(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[2])
//#define ITER_3(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_2(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[3])
//#define ITER_4(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_3(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[4])
//#define ITER_5(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_4(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[5])
//#define ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_5(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[6])
//#define ITER_7(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[7])
//#define ITER_8(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_7(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[8])
//#define ITER_9(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_8(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[9])
//#define ITER_10(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_9(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT)

//#define ITER(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT)
//
//static vector<string> V( {"Null", "LTV", "StSt", "BV", "FV", "BFVrns"} );
//
//ITER(V, GENERATE_PKE_TEST_CASE, Encrypt_Decrypt, EncryptionScalar, Poly)

#endif /* SRC_CORE_LIB_UTILS_TESTCASEGEN_H_ */
