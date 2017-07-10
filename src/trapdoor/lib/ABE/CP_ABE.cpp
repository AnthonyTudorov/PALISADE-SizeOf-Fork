/*
 * CP_ABE.cpp
 *
 *  Created on: Mar 23, 2017
 *      Author: savas
 */

#include "CP_ABE.h"

namespace lbcrypto {

	/*
	 * This is a setup function for Private Key Generator (PKG);
	 * generates master public key (MPK) and master secret key
	 * m_ell is the number of attributes
	 */
	std::pair<RingMat, RLWETrapdoorPair<Poly>> CPABE::Setup(
		shared_ptr<ILParams> ilParams,
		int32_t base,
		const usint ell, // number of attributes
		DiscreteUniformGenerator &dug,  // select according to uniform distribution
		Poly &u,
		RingMat &B,
		RingMat &nB
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) + 1;
		m_m = m_k + 2;
		m_ell = ell;
		m_base = base;

		if(u.GetFormat() != COEFFICIENT)
			u.SwitchFormat();
		u.SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
		u.SwitchFormat(); // always kept in EVALUATION format

		for (usint i = 0; i < B.GetRows(); i++)
			for (usint j = 0; j < B.GetCols(); j++) {
				if(B(i, j).GetFormat() != COEFFICIENT)
					B(i,j).SwitchFormat();
				B(i, j).SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
				B(i, j).SwitchFormat(); // always kept in EVALUATION format
			}

		for (usint i = 0; i < nB.GetRows(); i++)
			for (usint j = 0; j < nB.GetCols(); j++) {
				if(nB(i, j).GetFormat() != COEFFICIENT)
					nB(i,j).SwitchFormat();
				nB(i, j).SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
				nB(i, j).SwitchFormat(); // always kept in EVALUATION format
			}

		return RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);
	}

	/**
	 * This setup function is used by users; namely senders and receivers
	 * Initialize private members of the object such as modulus, cyclotomic order, etc.
	 * m_ell is the number of attributes
	 */
	void CPABE::Setup(
		const shared_ptr<ILParams> ilParams,
		int32_t base,
		const usint ell
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) + 1;

		m_m = m_k + 2;
		m_ell = ell;
		m_base = base;
	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
	void CPABE::KeyGen(
		const shared_ptr<ILParams> ilParams,
		const usint S[],							// Access rights of the user {0, 1}
		const RingMat &A,                         	// Public parameter $B \in R_q^{ell \times k}$
		const RingMat &B,                         	// Public parameter $B \in R_q^{ell \times k}$
		const RingMat &nB,                         	// Public parameter $B \in R_q^{ell \times k}$
		const Poly &u,                  		// public key $d \in R_q$
		const RLWETrapdoorPair<Poly> &T_A, 	// Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg,          	// to generate error terms (Gaussian)
		RingMat &sKey                           	// Secret key
	)
	{
		RingMat skB(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, COEFFICIENT, SIGMA), m_m, m_ell);
//		RingMat skB(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), m_m, m_ell);


	#pragma omp parallel for
		for(usint j=0; j < m_ell;j++){
			for(usint i = 0; i < m_m; i++)
				skB(i,j).SwitchFormat();
		}

		Poly y(ilParams, EVALUATION, true);
		Poly z(ilParams, EVALUATION, true);
		std::vector<Poly> z_vectors(m_ell);


	#pragma omp parallel for firstprivate(z) num_threads(4)
		for(usint i=0; i<m_ell; i++) {
			if(S[i]==1) {
				z = B(i, 0)*skB(0, i);
				for(usint j=1; j<m_m; j++)
					z += B(i, j)*skB(j, i);
			}
			else {
				z = nB(i, 0)*skB(0, i);
				for(usint j=1; j<m_m; j++)
					z += nB(i, j)*skB(j, i);
			}
		//		y += z;
			z_vectors.at(i) = z;
		}

		for(usint i=0; i < m_ell;i++){
			y += z_vectors.at(i);
		}

		y = u - y;

		double c = 2 * SIGMA;
		double s = SPECTRAL_BOUND(m_N, m_m - 2);
		DiscreteGaussianGenerator dggLargeSigma(sqrt(s * s - c * c));
		RingMat skA(Poly::MakeAllocator(ilParams, EVALUATION), m_m, 1);

		skA = RLWETrapdoorUtility::GaussSamp(m_N, m_k, A, T_A, y, m_base, SIGMA, dgg, dggLargeSigma);

		for(usint i=0; i<m_m; i++)
			sKey(i, 0) = skA(i, 0);

	#pragma omp parallel for num_threads(4)
		for(usint i=0; i<m_ell; i++)
			for(usint j=0; j<m_m; j++)
				sKey(j, i+1) = skB(j, i);
	}


	/* The encryption function takes public parameters A, B, and d, attribute values x and the plaintext pt
	 * and generates the ciphertext pair c0 and c1
	 * Note that B is two dimensional array of ring elements (matrix);
	 * Each row corresponds B_i for i = 0, 1, ... ell, where ell is the number of attributes
	 */
	void CPABE::Encrypt(
		shared_ptr<ILParams> ilParams,
		const RingMat &A,
		const RingMat &B,
		const RingMat &nB,
		const Poly &u,
		const int W[],                // Access structure {-1, 0, 1}
		const Poly &pt,
		DiscreteGaussianGenerator &dgg, // to generate error terms (Gaussian)
		DiscreteUniformGenerator &dug,  // select according to uniform distribution
		BinaryUniformGenerator &bug,    // select according to uniform distribution binary
		RingMat &CW,
		RingMat &C,
		RingMat &nC,
		Poly &c1
	)
	{
		usint lenW = 0;
		for(usint i=0; i<m_ell; i++)
			if(W[i]!=0)
				lenW++;
//		RingMat err(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), m_m, 2*m_ell+2-lenW);
		RingMat err(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, COEFFICIENT, SIGMA), m_m, 2*m_ell+2-lenW);
#pragma omp parallel for
		for(usint i=0; i < m_m;i++){
			for(usint j = 0; j < 2*m_ell+2-lenW;j++)
				err(i,j).SwitchFormat();
		}

		Poly s(dug, ilParams, COEFFICIENT);
		s.SwitchFormat();

		// A part
		usint iNoise = 0;
//#pragma omp parallel for
		for(usint j=0; j<m_m; j++)
			CW(0, j) = A(0, j)*s + err(j, iNoise);
		iNoise++;

		// B part
		usint iW = 0;
		usint iAW = 0;
//#pragma omp parallel for
		for (usint i=0; i<m_ell; i++)
		{
			if(W[i] == 1) {
				for(usint j=0; j<m_m; j++)
					CW(iW+1, j) = B(i, j)*s  + err(j, iNoise);
				iNoise++;
				iW++;
			}
			else if(W[i]==-1) {
				for(usint j=0; j<m_m; j++)
					CW(iW+1, j) = nB(i, j)*s + err(j, iNoise);
				iNoise++;
				iW++;
			}
			else {
				for(usint j=0; j<m_m; j++) {
					C(iAW, j) = B(i, j)*s  + err(j, iNoise);
					nC(iAW, j) = nB(i, j)*s + err(j, iNoise+1);

				}
				iNoise+=2;
				iAW++;
			}
		}

		// ***
		// compute c1
		Poly qHalf(ilParams, COEFFICIENT, true);
		qHalf += (m_q >> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		Poly err1(ilParams, COEFFICIENT, true); // error term
		err1.SetValues(dgg.GenerateVector(m_N, ilParams->GetModulus()), COEFFICIENT);
		err1.SwitchFormat();

		c1 = s*u + err1 + pt*qHalf;
	}

	/*
	 * Decryption function takes the ciphertext pair and the secret keys
	 * and yields the decrypted plaintext in COEFFICIENT form
	 */
	void CPABE::Decrypt(
		const shared_ptr<ILParams> ilParams,
		const int W[],                // Access structure {-1, 0, 1}
		const usint S[],                // Users attributes {0, 1}
		const RingMat &sKey,
		const RingMat &CW,
		const RingMat &C,
		const RingMat &nC,
		const Poly &c1,
		Poly &dtext
	)
	{
		dtext.SetValuesToZero();
		if(dtext.GetFormat() != EVALUATION)
			dtext.SwitchFormat();

		for(usint j=0; j<m_m; j++)
			dtext += CW(0, j)*sKey(j, 0);

		usint iW=0;
		usint iAW=0;
//#pragma omp parallel for
		for(usint i=0; i<m_ell; i++) {
			if (W[i] == 1  || W[i] == -1) {
				for(usint j=0; j<m_m; j++)
					dtext += CW(iW+1, j)*sKey(j, i+1);
				iW++;
			}
			else {
				if(S[i]==1)
					for(usint j=0; j<m_m; j++)
						dtext += C(iAW, j)*sKey(j, i+1);
				else
					for(usint j=0; j<m_m; j++)
						dtext += nC(iAW, j)*sKey(j, i+1);
				iAW++;
			}
		}

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

