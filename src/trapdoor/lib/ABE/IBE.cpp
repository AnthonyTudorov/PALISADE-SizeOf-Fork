/*
 * CP_ABE.cpp
 *
 *  Created on: Mar 23, 2017
 *      Author: savas
 */

#include "IBE.h"

namespace lbcrypto {

	/*
	 * This is a setup function for Private Key Generator (PKG);
	 * generates master public key (MPK) and master secret key
	 * m_ell is the number of attributes
	 */
	std::pair<RingMat, RLWETrapdoorPair<Poly>> IBE::Setup(
		shared_ptr<ILParams> ilParams,
		int32_t base,
		DiscreteUniformGenerator &dug  // select according to uniform distribution
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) + 1;
		m_m = m_k + 2;
		m_base = base;

		return RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);
	}

	/**
	 * This setup function is used by users; namely senders and receivers
	 * Initialize private members of the object such as modulus, cyclotomic order, etc.
	 * m_ell is the number of attributes
	 */
	void IBE::Setup(
		const shared_ptr<ILParams> ilParams,
		int32_t base
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) + 1;

		m_m = m_k + 2;
		m_base = base;
	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
	void IBE::KeyGen(
		const shared_ptr<ILParams> ilParams,
		const RingMat &A,                         // Public parameter $B \in R_q^{ell \times k}$
		const Poly &u,                  	  // public key of the user $u \in R_q$
		const RLWETrapdoorPair<Poly> &T_A,  // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg,           // to generate error terms (Gaussian)
		RingMat &sKey                             // Secret key                          	// Secret key
	)
	{
		double c = 2 * SIGMA;
		double s = SPECTRAL_BOUND(m_N, m_m - 2);
		DiscreteGaussianGenerator dggLargeSigma(sqrt(s * s - c * c));

		sKey = RLWETrapdoorUtility::GaussSamp(m_N, m_k, A, T_A, u, m_base, SIGMA, dgg, dggLargeSigma);
	}


	/* The encryption function takes public parameters A, B, and d, attribute values x and the plaintext pt
	 * and generates the ciphertext pair c0 and c1
	 * Note that B is two dimensional array of ring elements (matrix);
	 * Each row corresponds B_i for i = 0, 1, ... ell, where ell is the number of attributes
	 */
	void IBE::Encrypt(
		shared_ptr<ILParams> ilParams,
		const RingMat &A,
		const Poly &u,
		const Poly &pt,
		DiscreteGaussianGenerator &dgg, // to generate error terms (Gaussian)
		DiscreteUniformGenerator &dug,  // select according to uniform distribution
		BinaryUniformGenerator &bug,    // select according to uniform distribution binary
		RingMat &C0,
		Poly &c1
	)
	{
		RingMat err(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), m_m+1, 1);

		Poly s(dug, ilParams, COEFFICIENT);
		s.SwitchFormat();

		for(usint j=0; j<m_m; j++)
			C0(0, j) = A(0, j)*s + err(j, 0);

		// ***
		// compute c1
		Poly qHalf(ilParams, COEFFICIENT, true);
		qHalf += (m_q >> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		c1 = s*u + pt*qHalf  + err(m_m, 0);
	}

	/*
	 * Decryption function takes the ciphertext pair and the secret keys
	 * and yields the decrypted plaintext in COEFFICIENT form
	 */
	void IBE::Decrypt(
		const shared_ptr<ILParams> ilParams,
		const RingMat &sKey,
		const RingMat &C0,
		const Poly &c1,
		Poly &dtext
	)
	{
		dtext.SetValuesToZero();
		if(dtext.GetFormat() != EVALUATION)
			dtext.SwitchFormat();

		for(usint j=0; j<m_m; j++)
			dtext += C0(0, j)*sKey(j, 0);

		dtext = c1 - dtext;
		dtext.SwitchFormat();

		BigInteger dec, threshold = m_q >> 2, qHalf = m_q >> 1;
		for (usint i = 0; i < m_N; i++)
		{
			dec = dtext.GetValAtIndex(i);

			if (dec > qHalf)
				dec = m_q - dec;
			if (dec > threshold)
				dtext.SetValAtIndex(i, BigInteger::ONE);
			else
				dtext.SetValAtIndex(i, BigInteger::ZERO);
		}
	}
}

