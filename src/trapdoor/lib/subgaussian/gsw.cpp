/**
 * @file gsw.cpp Provides implementation of the GSW variant described in
 * https://eprint.iacr.org/2014/094
 *
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2018, New Jersey Institute of Technology (NJIT)
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

#ifndef _LBCRYPTO_SUBGAUSSIAN_GSW_CPP
#define _LBCRYPTO_SUBGAUSSIAN_GSW_CPP

#include "gsw.h"
#include "math/matrix-impl.cpp"

namespace lbcrypto {

	template class Matrix<NativeInteger>;

	template <class Integer,class Vector>
	shared_ptr<GSWSecretKey<Integer>> GSWScheme<Integer,Vector>::SecretKeyGen() const
	{
		shared_ptr<GSWSecretKey<Integer>> sk(new GSWSecretKey<Integer>([&](){return m_cryptoParams.GetDgg().GenerateInteger(m_cryptoParams.GetModulus());}, m_cryptoParams.Getn(), 1));
		return sk;
	}

	template <class Integer,class Vector>
	shared_ptr<GSWCiphertext<Integer>> GSWScheme<Integer,Vector>::Encrypt(const GSWPlaintext<Integer> &plaintext, const shared_ptr<GSWSecretKey<Integer>> sk) const
	{
		Matrix<Integer> cbar([&](){return m_cryptoParams.GetDug().GenerateInteger();}, m_cryptoParams.Getn()-1, m_cryptoParams.Getn()*m_cryptoParams.Getl());
		Matrix<Integer> et([&](){return m_cryptoParams.GetDgg().GenerateInteger(m_cryptoParams.GetModulus());}, 1,m_cryptoParams.Getm());
		Matrix<Integer> skt = sk->Transpose();
		Matrix<Integer> bt = et - skt.Mult(cbar);
		Matrix<Integer> cStack = cbar.VStack(bt);
		Matrix<Integer> g([&](){return Integer(0);}, m_cryptoParams.Getn(),m_cryptoParams.Getn()*m_cryptoParams.Getl());
		g = g.GadgetVector(m_cryptoParams.GetBase());
		shared_ptr<Matrix<Integer>> c(new Matrix<Integer>(cStack + g.ScalarMult(plaintext)));
		return c;
	}

}

#endif
