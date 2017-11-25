/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 * @programmer Erkay Savas
 * @version 00_05
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
 * This code provides functionality for Identity-based encryption (IBE). IBE is like a one attribute CP-ABE
 * The algorithms and some of the naming convenstions are based on the paper in
 * https://link.springer.com/content/pdf/10.1007/978-3-642-34704-7.pdf#page=333
 */

#include "ibe.h"

namespace lbcrypto {

	/*
	 * This is a setup function for Private Key Generator (PKG);
	 * generates master public key (MPK) and master secret key
	 * m_ell is the number of attributes
	 */
	std::pair<RingMat, RLWETrapdoorPair<Poly>> IBE::SetupPKG(
		const shared_ptr<ILParams> ilParams,
		int32_t base
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) /*+ 1*/;
		m_m = m_k + 2;
		m_base = base;

		return RLWETrapdoorUtility<Poly>::TrapdoorGen(ilParams, SIGMA, base);
	}

	/**
	 * This setup function is used by users; namely senders and receivers
	 * Initialize private members of the object such as modulus, cyclotomic order, etc.
	 * m_ell is the number of attributes
	 */
	void IBE::SetupNonPKG(
		const shared_ptr<ILParams> ilParams,
		int32_t base
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) /*+ 1*/;

		m_m = m_k + 2;
		m_base = base;
	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
	void IBE::KeyGen(
		const RingMat &pubA,                         // Public parameter $B \in R_q^{ell \times k}$
		const Poly &pubElemD,                  	  // public key of the user $u \in R_q$
		const RLWETrapdoorPair<Poly> &secTA,  // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg,           // to generate error terms (Gaussian)
		RingMat *sk                             // Secret key                          	// Secret key
	)
	{
		DiscreteGaussianGenerator dggLargeSigma;

		dggLargeSigma = dgg;

		*sk = RLWETrapdoorUtility<Poly>::GaussSamp(m_N, m_k, pubA, secTA, pubElemD, dgg, dggLargeSigma, m_base);
	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
	shared_ptr<RingMat> IBE::KeyGenOffline(
		const RLWETrapdoorPair<Poly> &secTA,  // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg           // to generate error terms (Gaussian)
	)
	{

		DiscreteGaussianGenerator dggLargeSigma;

		dggLargeSigma = dgg;

		shared_ptr<RingMat> pertubationVector =  RLWETrapdoorUtility<Poly>::GaussSampOffline(m_N, m_k, secTA, dgg, dggLargeSigma, m_base);

		return pertubationVector;

	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
	void IBE::KeyGenOnline(
		const RingMat &pubA,                         // Public parameter $B \in R_q^{ell \times k}$
		const Poly &pubElemD,                  	  // public key of the user $u \in R_q$
		const RLWETrapdoorPair<Poly> &secTA,  // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg,           // to generate error terms (Gaussian)
		const shared_ptr<RingMat> perturbationVector, //perturbation vector
		RingMat *sk                             // Secret key                          	// Secret key
	)
	{
		*sk = RLWETrapdoorUtility<Poly>::GaussSampOnline(m_N, m_k, pubA, secTA, pubElemD, dgg, perturbationVector, m_base);
	}

	/* The encryption function takes public parameters A, B, and d, attribute values x and the plaintext pt
	 * and generates the ciphertext pair c0 and c1
	 */
	void IBE::Encrypt(
		shared_ptr<ILParams> ilParams,
		const RingMat &pubA,
		const Poly &pubElemD,
		const Poly &ptext,
		DiscreteUniformGenerator &dug,  // select according to uniform distribution
		RingMat *ctC0,
		Poly *ctC1
	)
	{
//		RingMat err(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), m_m+1, 1);

		RingMat err(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, COEFFICIENT, SIGMA),m_m+1, 1);

#pragma omp parallel for num_threads(4)
		for(usint i=0; i < m_m+1;i++){
				err(i,0).SwitchFormat();
		}

		Poly s(dug, ilParams, COEFFICIENT);
		s.SwitchFormat();

		for(usint j=0; j<m_m; j++)
			(*ctC0)(0, j) = pubA(0, j)*s + err(j, 0);

		// compute c1
		Poly qHalf(ilParams, COEFFICIENT, true);
		qHalf += (m_q >> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		*ctC1 = s*pubElemD + ptext*qHalf  + err(m_m, 0);
	}

	/*
	 * Decryption function takes the ciphertext pair and the secret keys
	 * and yields the decrypted plaintext in COEFFICIENT form
	 */
	void IBE::Decrypt(
		const RingMat &sk,
		const RingMat &ctC0,
		const Poly &ctC1,
		Poly *dtext
	)
	{
		dtext->SetValuesToZero();
		if(dtext->GetFormat() != EVALUATION)
			dtext->SwitchFormat();

		for(usint j=0; j<m_m; j++)
			*dtext += ctC0(0, j)*sk(j, 0);

		*dtext = ctC1 - *dtext;
		dtext->SwitchFormat();

		BigInteger dec, threshold = m_q >> 2, qHalf = m_q >> 1;
		for (usint i = 0; i < m_N; i++)
		{
			dec = dtext->at(i);

			if (dec > qHalf)
				dec = m_q - dec;
			if (dec > threshold)
			  dtext->at(i)= BigInteger(1);
			else
			  dtext->at(i)= BigInteger(0);
		}
	}
}

