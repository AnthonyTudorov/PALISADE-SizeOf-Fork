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
template <class Element>
	std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> IBE<Element>::SetupPKG(
		const shared_ptr<typename Element::Params> ilParams,
		int32_t base
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		typename Element::Integer q(ilParams->GetModulus());
		m_q = q;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) /*+ 1*/;
		m_m = m_k + 2;
		m_base = base;

		return RLWETrapdoorUtility<Element>::TrapdoorGen(ilParams, SIGMA, base);
	}

	/**
	 * This setup function is used by users; namely senders and receivers
	 * Initialize private members of the object such as modulus, cyclotomic order, etc.
	 * m_ell is the number of attributes
	 */
template <class Element>
	void IBE<Element>::SetupNonPKG(
		const shared_ptr<typename Element::Params> ilParams,
		int32_t base
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		typename Element::Integer q(ilParams->GetModulus());
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
template <class Element>
	void IBE<Element>::KeyGen(
		const Matrix<Element> &pubA,                         // Public parameter $B \in R_q^{ell \times k}$
		const Element &pubElemD,                  	  // public key of the user $u \in R_q$
		const RLWETrapdoorPair<Element> &secTA,  // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		typename Element::DggType &dgg,           // to generate error terms (Gaussian)
		Matrix<Element> *sk                             // Secret key                          	// Secret key
	)
	{
		typename Element::DggType dggLargeSigma;

		dggLargeSigma = dgg;

		*sk = RLWETrapdoorUtility<Element>::GaussSamp(m_N, m_k, pubA, secTA, pubElemD, dgg, dggLargeSigma, m_base);
	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
template <class Element>
	shared_ptr<Matrix<Element>> IBE<Element>::KeyGenOffline(
		const RLWETrapdoorPair<Element> &secTA,  // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		typename Element::DggType &dgg           // to generate error terms (Gaussian)
	)
	{

		typename Element::DggType dggLargeSigma;

		dggLargeSigma = dgg;

		shared_ptr<Matrix<Element>> pertubationVector =  RLWETrapdoorUtility<Element>::GaussSampOffline(m_N, m_k, secTA, dgg, dggLargeSigma, m_base);

		return pertubationVector;

	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
template <class Element>
	void IBE<Element>::KeyGenOnline(
		const Matrix<Element> &pubA,                         // Public parameter $B \in R_q^{ell \times k}$
		const Element &pubElemD,                  	  // public key of the user $u \in R_q$
		const RLWETrapdoorPair<Element> &secTA,  // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		typename Element::DggType &dgg,           // to generate error terms (Gaussian)
		const shared_ptr<Matrix<Element>> perturbationVector, //perturbation vector
		Matrix<Element> *sk                             // Secret key                          	// Secret key
	)
	{
		*sk = RLWETrapdoorUtility<Element>::GaussSampOnline(m_N, m_k, pubA, secTA, pubElemD, dgg, perturbationVector, m_base);
	}

	/* The encryption function takes public parameters A, B, and d, attribute values x and the plaintext pt
	 * and generates the ciphertext pair c0 and c1
	 */
template <class Element>
	void IBE<Element>::Encrypt(
		shared_ptr<typename Element::Params> ilParams,
		const Matrix<Element> &pubA,
		const Element &pubElemD,
		const Element &ptext,
		typename Element::DugType &dug,  // select according to uniform distribution
		Matrix<Element> *ctC0,
		Element *ctC1
	)
	{
//		Matrix<Element> err(Element::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), m_m+1, 1);

		Matrix<Element> err(Element::MakeDiscreteGaussianCoefficientAllocator(ilParams, COEFFICIENT, SIGMA),m_m+1, 1);

#pragma omp parallel for num_threads(4)
		for(usint i=0; i < m_m+1;i++){
				err(i,0).SwitchFormat();
		}

		Element s(dug, ilParams, COEFFICIENT);
		s.SwitchFormat();

		for(usint j=0; j<m_m; j++)
			(*ctC0)(0, j) = pubA(0, j)*s + err(j, 0);

		// compute c1
		Element qHalf(ilParams, COEFFICIENT, true);
		qHalf += (m_q >> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		*ctC1 = s*pubElemD + ptext*qHalf  + err(m_m, 0);
	}

	/*
	 * Decryption function takes the ciphertext pair and the secret keys
	 * and yields the decrypted plaintext in COEFFICIENT form
	 */
template <class Element>
	void IBE<Element>::Decrypt(
		const Matrix<Element> &sk,
		const Matrix<Element> &ctC0,
		const Element &ctC1,
		Element *dtext
	)
	{
		dtext->SetValuesToZero();
		if(dtext->GetFormat() != EVALUATION)
			dtext->SwitchFormat();

		for(usint j=0; j<m_m; j++)
			*dtext += ctC0(0, j)*sk(j, 0);

		*dtext = ctC1 - *dtext;
		dtext->SwitchFormat();

		typename Element::Integer dec, threshold = m_q >> 2, qHalf = m_q >> 1;
		for (usint i = 0; i < m_N; i++)
		{
			dec = dtext->at(i);

			if (dec > qHalf)
				dec = m_q - dec;
			if (dec > threshold)
			  dtext->at(i)= typename Element::Integer(1);
			else
			  dtext->at(i)= typename Element::Integer(0);
		}
	}
}

