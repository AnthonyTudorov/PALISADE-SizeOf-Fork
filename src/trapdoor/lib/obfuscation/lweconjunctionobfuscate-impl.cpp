/**
 * @file lweconjunctionobfuscate-impl.cpp Implementation of conjunction obfuscator as described in https://eprint.iacr.org/2017/844.pdf
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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

#include "../../core/lib/math/matrix.cpp"
#include "lweconjunctionobfuscate.cpp"

namespace lbcrypto {

template class ClearLWEConjunctionPattern<Poly>;
template class ObfuscatedLWEConjunctionPattern<Poly>;
template class LWEConjunctionObfuscationAlgorithm<Poly>;

template class ClearLWEConjunctionPattern<DCRTPoly>;
template class ObfuscatedLWEConjunctionPattern<DCRTPoly>;
template class LWEConjunctionObfuscationAlgorithm<DCRTPoly>;
	
template <>
shared_ptr<typename Poly::Params> LWEConjunctionObfuscationAlgorithm<Poly>::GenerateElemParams(double q, uint32_t n) const {

	typename Poly::Integer qPrime = FirstPrime<typename Poly::Integer>(floor(log2(q - 1.0)) + 1.0, 2 * n);
	typename Poly::Integer rootOfUnity = RootOfUnity<typename Poly::Integer>(2 * n, qPrime);

	//Prepare for parameters.
	shared_ptr<typename Poly::Params> params(new typename Poly::Params(2 * n, qPrime, rootOfUnity));

	return params;

}

template <>
shared_ptr<typename DCRTPoly::Params> LWEConjunctionObfuscationAlgorithm<DCRTPoly>::GenerateElemParams(double q, uint32_t n) const {

	size_t dcrtBits = 60;
	size_t size = ceil((floor(log2(q - 1.0)) + 2.0) / (double)dcrtBits);

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);

	//makes sure the first integer is less than 2^60-1 to take advangate of NTL optimizations
	NativeInteger firstInteger = FirstPrime<NativeInteger>(dcrtBits, 2 * n);
	firstInteger -= 2*n*((uint64_t)(1)<<40);
	moduli[0] = NextPrime<NativeInteger>(firstInteger, 2 * n);
	roots[0] = RootOfUnity<NativeInteger>(2 * n, moduli[0]);

	for (size_t i = 1; i < size; i++)
	{
		moduli[i] = NextPrime<NativeInteger>(moduli[i-1], 2 * n);
		roots[i] = RootOfUnity<NativeInteger>(2 * n, moduli[i]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(2 * n, moduli, roots));

	ChineseRemainderTransformFTT<NativeVector>::PreCompute(roots,2*n,moduli);

	return params;

}

}
