/*
 * CP_ABE.cpp
 *
 *  Created on: Mar 23, 2017
 *      Author: savas
 */

#include "cp_abe.h"

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
		const DiscreteUniformGenerator &dug,  // select according to uniform distribution
		Poly *pubElemD,			  // dug polynomial generated based on algorithm
		RingMat *pubElemBPos, // Bi +, for each attribute, there is a vector of polynomials for when an attribute is equal to 1
		RingMat *pubElemBNeg  // Bi -, for each attribute, there is a vector of polynomials for when an attribute is equal to 0
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) /*+ 1*/;
		m_m = m_k + 2;
		m_ell = ell;
		m_base = base;

		if(pubElemD->GetFormat() != COEFFICIENT)
			pubElemD->SwitchFormat();
		pubElemD->SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
		pubElemD->SwitchFormat(); // always kept in EVALUATION format

		for (usint i = 0; i < pubElemBPos->GetRows(); i++)
			for (usint j = 0; j < pubElemBPos->GetCols(); j++) {
				if((*pubElemBPos)(i, j).GetFormat() != COEFFICIENT)
					(*pubElemBPos)(i,j).SwitchFormat();
				(*pubElemBPos)(i, j).SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
				(*pubElemBPos)(i, j).SwitchFormat(); // always kept in EVALUATION format
			}

		for (usint i = 0; i < pubElemBNeg->GetRows(); i++)
			for (usint j = 0; j < pubElemBNeg->GetCols(); j++) {
				if((*pubElemBNeg)(i, j).GetFormat() != COEFFICIENT)
					(*pubElemBNeg)(i,j).SwitchFormat();
				(*pubElemBNeg)(i, j).SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
				(*pubElemBNeg)(i, j).SwitchFormat(); // always kept in EVALUATION format
			}

		return RLWETrapdoorUtility<Poly>::TrapdoorGen(ilParams, SIGMA, base, false);
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
		m_k = (usint)floor(logTwo) /*+ 1*/;

		m_m = m_k + 2;
		m_ell = ell;
		m_base = base;
	}

	/* Given public parameter d and a public key B positive (pubElementBPos) and B Negative (pubElemBNeg),
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this function as it needs the secret element of a trapdoor T_A */
	void CPABE::KeyGen(
		const shared_ptr<ILParams> ilParams,
		const usint s[],							// Access rights of the user {0, 1}
		const RingMat &pubTA,                         	// Public parameter from trapdoor sampled from R_q^{ell \times k}$
		const RingMat &pubElemBPos,            // Public parameter B positive sampled from R_q^{ell \times k}$
		const RingMat &pubElemBNeg,            // Public parameter B negative sampled from R_q^{ell \times k}$
		const Poly &pubElemD,                  		// public parameter $d \in R_q$
		const RLWETrapdoorPair<Poly> &secTA, 	// Secret parameter from trapdoor $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg,          	// to generate error terms (Gaussian)
		RingMat *sk                           	// Secret key
	)
	{
		RingMat skB(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, COEFFICIENT, SIGMA), m_m, m_ell);

//	#pragma omp parallel for
		for(usint j=0; j < m_ell;j++){
			for(usint i = 0; i < m_m; i++)
				skB(i,j).SwitchFormat();
		}

		Poly y(ilParams, EVALUATION, true);
		Poly z(ilParams, EVALUATION, true);
		std::vector<Poly> z_vectors(m_ell);

//	#pragma omp parallel for firstprivate(z) num_threads(4)
		for(usint i=0; i<m_ell; i++) {
			if(s[i]==1) {
				z = pubElemBPos(i, 0)*skB(0, i);
				for(usint j=1; j<m_m; j++)
					z += pubElemBPos(i, j)*skB(j, i);
			}
			else {
				z = pubElemBNeg(i, 0)*skB(0, i);
				for(usint j=1; j<m_m; j++)
					z += pubElemBNeg(i, j)*skB(j, i);
			}
			z_vectors.at(i) = z;
		}

		for(usint i=0; i < m_ell;i++){
			y += z_vectors.at(i);
		}

		y = pubElemD - y;

		DiscreteGaussianGenerator dggLargeSigma;

		dggLargeSigma = dgg;

		RingMat skA(Poly::MakeAllocator(ilParams, EVALUATION), m_m, 1);

		skA = RLWETrapdoorUtility<Poly>::GaussSamp(m_N, m_k, pubTA, secTA, y, dgg, dggLargeSigma, m_base);

		for(usint i=0; i<m_m; i++)
			(*sk)(i, 0) = skA(i, 0);

//	#pragma omp parallel for num_threads(4)
		for(usint i=0; i<m_ell; i++)
			for(usint j=0; j<m_m; j++)
				(*sk)(j, i+1) = skB(j, i);
	}


/* Given public parameter d and a public key B positive (pubElementBPos) and B Negative (pubElemBNeg),
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this function as it needs the secret element of a trapdoor T_A */
	void CPABE::KeyGenOnline(
		const shared_ptr<ILParams> ilParams,
		const usint s[],							// Access rights of the user {0, 1}
		const RingMat &pubTA,                         	// Public parameter from trapdoor sampled from R_q^{ell \times k}$
		const RingMat &pubElemBPos,            // Public parameter B positive sampled from R_q^{ell \times k}$
		const RingMat &pubElemBNeg,            // Public parameter B negative sampled from R_q^{ell \times k}$
		const Poly &pubElemD,                  		// public parameter $d \in R_q$
		const RLWETrapdoorPair<Poly> &secTA, 	// Secret parameter from trapdoor $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg,          	// to generate error terms (Gaussian)
		const shared_ptr<RingMat> perturbationVector,
		RingMat *sk                           	// Secret key
	)
	{
		RingMat skB(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, COEFFICIENT, SIGMA), m_m, m_ell);

//	#pragma omp parallel for
		for(usint j=0; j < m_ell;j++){
			for(usint i = 0; i < m_m; i++)
				skB(i,j).SwitchFormat();
		}

		Poly y(ilParams, EVALUATION, true);
		Poly z(ilParams, EVALUATION, true);
		std::vector<Poly> z_vectors(m_ell);

//	#pragma omp parallel for firstprivate(z) num_threads(4)
		for(usint i=0; i<m_ell; i++) {
			if(s[i]==1) {
				z = pubElemBPos(i, 0)*skB(0, i);
				for(usint j=1; j<m_m; j++)
					z += pubElemBPos(i, j)*skB(j, i);
			}
			else {
				z = pubElemBNeg(i, 0)*skB(0, i);
				for(usint j=1; j<m_m; j++)
					z += pubElemBNeg(i, j)*skB(j, i);
			}
			z_vectors.at(i) = z;
		}

		for(usint i=0; i < m_ell;i++){
			y += z_vectors.at(i);
		}

		y = pubElemD - y;

		RingMat skA(Poly::MakeAllocator(ilParams, EVALUATION), m_m, 1);

		skA = RLWETrapdoorUtility<Poly>::GaussSampOnline(m_N, m_k, pubTA, secTA, y, dgg, perturbationVector, m_base);

		for(usint i=0; i<m_m; i++)
			(*sk)(i, 0) = skA(i, 0);

//	#pragma omp parallel for num_threads(4)
		for(usint i=0; i<m_ell; i++)
			for(usint j=0; j<m_m; j++)
				(*sk)(j, i+1) = skB(j, i);
	}

/* Given public parameter d and a public key B positive (pubElementBPos) and B Negative (pubElemBNeg),
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this function as it needs the secret element of a trapdoor T_A */
	shared_ptr<RingMat> CPABE::KeyGenOffline(
		const RLWETrapdoorPair<Poly> &secTA, 	// Secret parameter from trapdoor $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg         	// to generate error terms (Gaussian)
	)
	{
		DiscreteGaussianGenerator dggLargeSigma;
		dggLargeSigma = dgg;

		return RLWETrapdoorUtility<Poly>::GaussSampOffline(m_N, m_k, secTA, dgg, dggLargeSigma, m_base);
	}
	/* The encryption function takes public parameters trapdoor pubTA, publicElemBPos and publicElemBNeg, and d (u), attribute values w and the plaintext pt
	 * and generates the ciphertext pair c0 and c1
	 * Note that B is two dimensional array of ring elements (matrix);
	 * Each row corresponds B_i for i = 0, 1, ... ell, where ell is the number of attributes
	 */
	void CPABE::Encrypt(
		shared_ptr<ILParams> ilParams,
		const RingMat &pubTA,
		const RingMat &pubElemBPos,
		const RingMat &pubElemBNeg,
		const Poly &pubElemD,
		const int w[],                // Access structure {-1, 0, 1}
		const Poly &ptext,
		DiscreteGaussianGenerator &dgg, // to generate error terms (Gaussian)
		DiscreteUniformGenerator &dug,  // select according to uniform distribution
		RingMat *ctW,
		RingMat *cPos,
		RingMat *cNeg,
		Poly *ctC1
	)
	{
		usint lenW = 0;
		for(usint i=0; i<m_ell; i++)
			if(w[i]!=0)
				lenW++;

		RingMat err(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, COEFFICIENT, SIGMA), m_m, 2*m_ell+2-lenW);
#pragma omp parallel for num_threads(4)
		for(usint i=0; i < m_m;i++){
			for(usint j = 0; j < 2*m_ell+2-lenW;j++)
				err(i,j).SwitchFormat();
		}

		Poly s(dug, ilParams, COEFFICIENT);
		s.SwitchFormat();

		// A part
		usint iNoise = 0;
//#pragma omp parallel for num_threads(4)
		for(usint j=0; j<m_m; j++)
			(*ctW)(0, j) = pubTA(0, j)*s + err(j, iNoise);
		iNoise++;

		// B part
		usint iW = 0;
		usint iAW = 0;
//#pragma omp parallel for num_threads(4)
		for (usint i=0; i<m_ell; i++)
		{
			if(w[i] == 1) {
				for(usint j=0; j<m_m; j++)
					(*ctW)(iW+1, j) = pubElemBPos(i, j)*s  + err(j, iNoise);
				iNoise++;
				iW++;
			}
			else if(w[i]==-1) {
				for(usint j=0; j<m_m; j++)
					(*ctW)(iW+1, j) = pubElemBNeg(i, j)*s + err(j, iNoise);
				iNoise++;
				iW++;
			}
			else {
				for(usint j=0; j<m_m; j++) {
					(*cPos)(iAW, j) = pubElemBPos(i, j)*s  + err(j, iNoise);
					(*cNeg)(iAW, j) = pubElemBNeg(i, j)*s + err(j, iNoise+1);

				}
				iNoise+=2;
				iAW++;
			}
		}

		// compute c1
		Poly qHalf(ilParams, COEFFICIENT, true);
		qHalf += (m_q >> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		Poly err1(ilParams, COEFFICIENT, true); // error term
		err1.SetValues(dgg.GenerateVector(m_N, ilParams->GetModulus()), COEFFICIENT);
		err1.SwitchFormat();

		*ctC1 = s*pubElemD + err1 + ptext*qHalf;
	}

	/*
	 * Decryption function takes the ciphertext pair and the secret keys
	 * and yields the decrypted plaintext in COEFFICIENT form
	 */
	void CPABE::Decrypt(
		const int w[],                // Access structure {-1, 0, 1}
		const usint s[],                // Users attributes {0, 1}
		const RingMat &sk,
		const RingMat &ctW,
		const RingMat &cPos,
		const RingMat &cNeg,
		const Poly &ctC1,
		Poly *dtext
	)
	{
		dtext->SetValuesToZero();
		if(dtext->GetFormat() != EVALUATION)
			dtext->SwitchFormat();

		for(usint j=0; j<m_m; j++)
			*dtext += ctW(0, j)*sk(j, 0);

		usint iW=0;
		usint iAW=0;
//#pragma omp parallel for
		for(usint i=0; i<m_ell; i++) {
			if (w[i] == 1  || w[i] == -1) {
				for(usint j=0; j<m_m; j++)
					*dtext += ctW(iW+1, j)*sk(j, i+1);
				iW++;
			}
			else {
				if(s[i]==1)
					for(usint j=0; j<m_m; j++)
						*dtext += cPos(iAW, j)*sk(j, i+1);
				else
					for(usint j=0; j<m_m; j++)
						*dtext += cNeg(iAW, j)*sk(j, i+1);
				iAW++;
			}
		}

		*dtext = ctC1 - *dtext;
		dtext->SwitchFormat();

		BigInteger dec, threshold = m_q >> 2, qHalf = m_q >> 1;
		for (usint i = 0; i < m_N; i++)
		{
			dec = dtext->at(i);

			if (dec > qHalf)
				dec = m_q - dec;
			if (dec > threshold)
			  dtext->at(i)= 1;
			else
			  dtext->at(i)= BigInteger(0);
		}
	}
}

