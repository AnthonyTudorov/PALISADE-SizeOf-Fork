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
 * This code provides functionality for KP_ABE. The algorithms and naming conventions can be found from
 * this paper: https://eprint.iacr.org/2017/601.pdf
 */

#include "KP_ABE.h"

namespace lbcrypto {

	/*
	 * Input: base
	 * Input: vector of (k+2) elements of $R_q$
	 * Input: $k = \lceil \log_(base){q} \rceil$; i.e. the digit length of the modulus + 1 (in base)
	 * Output: matrix of (k+2)x(k+2) elements of $R_2$ where the coefficients are in balanced representation
	 */
	int polyVec2BalDecom (const shared_ptr<ILParams> ilParams, int32_t base, int k, const RingMat &publicElementB, RingMat *psi)
	{
		usint ringDimesion = ilParams->GetCyclotomicOrder() >> 1;
		usint m = k+2;
		BigInteger q = ilParams->GetModulus();

		auto big0 = BigInteger::ZERO;
		auto bigBase = BigInteger(base);

		for(usint i=0; i<m; i++)
			for(usint j=0; j<m; j++) {
				(*psi)(j, i).SetValuesToZero();
				if ((*psi)(j, i).GetFormat() != COEFFICIENT)
					(*psi)(j, i).SwitchFormat();
			}

		for (usint ii=0; ii<m; ii++) {
			int digit_i;

			auto tB = publicElementB(0, ii);
			if(tB.GetFormat() != COEFFICIENT)
				tB.SwitchFormat();

			for(usint i=0; i<ringDimesion; i++) {
				auto coeff_i = tB.GetValAtIndex(i);
				int j = 0;
				int flip = 0;
				while(coeff_i > big0) {
					digit_i = coeff_i.GetDigitAtIndex(1, base);
					if (digit_i > (base>>1)) {
						digit_i = base-digit_i;
#if MATHBACKEND == 7
						coeff_i = coeff_i+base;    // math backend 7
#else //if MATHBACKEND == 2
						coeff_i = coeff_i+Bigbase;    // math backend 2
#endif
						(*psi)(j, ii).SetValAtIndex(i, q-BigInteger(digit_i));
					}
					else if(digit_i == (base>>1)) {
						if (flip == 0) {
#if MATHBACKEND == 7
							coeff_i = coeff_i+base;  // math backend 7
#else //if MATHBACKEND == 2
							coeff_i = coeff_i+Bigbase;    // math backend 2
#endif
							(*psi)(j, ii).SetValAtIndex(i, q-BigInteger(digit_i));
						}
						else
							(*psi)(j, ii).SetValAtIndex(i, BigInteger(digit_i));
						flip = flip ^ 1;
					}
					else
						(*psi)(j, ii).SetValAtIndex(i, BigInteger(digit_i));

					coeff_i = coeff_i.DividedBy(bigBase);
					j++;
				}
			}
		}

		psi->SwitchFormat();

		return 0;
	}

	/*
	 * Input: vector of (k+2) elements of $R_q$
	 * Input: $k = \lceil \log_2{q} \rceil$; i.e. the bit length of the modulus + 1
	 * Output: matrix of (k+2)x(k+2) elements of $R_2$ where the coefficients are in NAF
	 */
	int polyVec2NAFDecom (const shared_ptr<ILParams> ilParams, int k, const RingMat &publicElementB, RingMat *psi)
	{
		usint ringDimension = ilParams->GetCyclotomicOrder() >> 1;
		usint m = k+2;
		BigInteger q = ilParams->GetModulus();
		BigInteger q1 = q-BigInteger::ONE;

		auto big0 = BigInteger::ZERO;
		auto big1 = BigInteger::ONE;
		auto big2 = BigInteger::TWO;
		auto big4 = BigInteger::FOUR;

		for(usint i=0; i<m; i++)
			for(usint j=0; j<m; j++) {
				(*psi)(j, i).SetValuesToZero();
				if ((*psi)(j, i).GetFormat() != COEFFICIENT)
					(*psi)(j, i).SwitchFormat();
			}

		for (usint ii=0; ii<m; ii++) {
			int k_i;

			auto tB = publicElementB(0, ii);
			if(tB.GetFormat() != COEFFICIENT)
				tB.SwitchFormat();

			for(usint i=0; i<ringDimension; i++) {
				auto coeff_i = tB.GetValAtIndex(i);
				int j = 0;
				while(coeff_i > big0) {
					k_i = coeff_i.GetBitAtIndex(1);

					if(k_i == 1) {
						k_i = 2 - coeff_i.Mod(big4).ConvertToInt();
						if(k_i == 1)
							coeff_i = coeff_i - big1;
						else
							coeff_i = coeff_i + big1;
					}
					else
						k_i = 0;

					coeff_i = coeff_i.DividedBy(big2);

					if(k_i == 1)
						(*psi)(j, ii).SetValAtIndex(i, big1);
					else if(k_i == -1)
						(*psi)(j, ii).SetValAtIndex(i, q1);
					else
						(*psi)(j, ii).SetValAtIndex(i, big0);
					j++;
				}
			}
		}

		psi->SwitchFormat();

		return 0;
	}

	/*
	 * This is a setup function for Private Key Generator (PKG);
	 * generates master public key (MPK) and master secret key
	 * m_ell is the number of attributes
	 */
	void KPABE::Setup(
		const shared_ptr<ILParams> ilParams,
		int32_t base,
		usint ell, // number of attributes
		const DiscreteUniformGenerator &dug,  // select according to uniform distribution
		RingMat *publicElementB
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;
		m_base = base;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) + 1;

		m_m = m_k + 2;

		m_ell = ell;

		for (usint i = 0; i < (*publicElementB).GetRows(); i++)
			for (usint j = 0; j < (*publicElementB).GetCols(); j++) {
				if((*publicElementB)(i, j).GetFormat() != COEFFICIENT)
					(*publicElementB)(i,j).SwitchFormat();
				(*publicElementB)(i, j).SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
				(*publicElementB)(i, j).SwitchFormat(); // always kept in EVALUATION format
			}
	}

	/**
	 * This setup function is used by users; namely senders and receivers
	 * Initialize private members of the object such as modulus, cyclotomic order, etc.
	 * m_ell is the number of attributes
	 */
	void KPABE::Setup(
		const shared_ptr<ILParams> ilParams,
		int32_t base,
		const usint ell
	)
	{
		m_N = ilParams->GetCyclotomicOrder() >> 1;
		BigInteger q(ilParams->GetModulus());
		m_q = q;
		m_base = base;

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		m_k = (usint)floor(logTwo) + 1;

		m_m = m_k + 2;

		m_ell = ell;
	}

	/*
	 * Given public parameters, attribute values and ciphertexts corresponding to attributes,
	 * computes the ciphertext and the public key evalPubElement for the circuit of attributes
	 * m_ell is the number of attributes and the circuit is assumed to be a binary tree of NAND gates
	 * Thus, m_ell must be a power of two
	 */
	void KPABE::EvalPK(
		const shared_ptr<ILParams> ilParams,
		const RingMat &publicElementB,
		RingMat *evalPubElementBf
	)
	{
		auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

		usint gateCnt = m_ell - 1;

		RingMat psi(zero_alloc, m_m, m_m); // Needed for bit decomposition matrices
		// w stands for wire
		RingMat wpublicElementB(zero_alloc, gateCnt, m_m);   // Bis associated with internal wires of the circuit
		// Temporary variables for bit decomposition operation
		RingMat negpublicElementB(zero_alloc, 1, m_m);       // EVALUATION (NTT domain)
		std::vector<Poly> digitsC1(m_m);

		// Input level of the circuit
		usint t = m_ell >> 1;  // the number of the gates in the first level (the number of input gates)
		for (usint i = 0; i < t; i++) // looping to evaluate and calculate w, wB, wC and R for all first level input gates
		{

			for (usint j = 0; j < m_m; j++)     // Negating Bis for bit decomposition
				negpublicElementB(0, j) = publicElementB(2*i+1, j).Negate();

			polyVec2BalDecom (ilParams, m_base, m_k, negpublicElementB, &psi);

			/* Psi^T*C2 and B2*Psi */
			for (usint j = 0; j < m_m; j++) { // the following two for loops are for vector matrix multiplication (a.k.a B(i+1) * BitDecompose(-Bi) and  gamma (0, 2) (for the second attribute of the circuit) * bitDecompose(-B))
				wpublicElementB(i, j) = publicElementB(2*i+2, 0)*psi(0, j); // B2 * BD(-Bi)
				for (usint k = 1; k < m_m; k++) {
					wpublicElementB(i, j) += publicElementB(2*i+2, k)*psi(k, j);
				}
			}

			for (usint j = 0; j < m_m; j++)
			{
				wpublicElementB(i, j) = publicElementB(0, j) - wpublicElementB(i, j);
			}
		}

		/* For internal wires of the circuit.
		 * Depth 0 refers to the circuit level where the input gates are located.
		 * Thus, we start with depth 1
		 */
		usint depth = log2(m_ell);
		for(usint d=1; d<depth; d++)
		{
			usint inStart = m_ell - (m_ell >> (d-1)); // Starting index for the input wires in level d
			usint outStart = m_ell - (m_ell >> d);    // Starting index for the output wires in level d
			usint gCntinLeveld = m_ell >> (d+1);      // number of gates in level d

			for (usint i = 0; i<gCntinLeveld; i++)
			{
				for (usint j = 0; j < m_m; j++)
					negpublicElementB(0, j) = wpublicElementB(inStart+2*i, j).Negate();

				polyVec2BalDecom (ilParams, m_base, m_k, negpublicElementB, &psi);

				for (usint j = 0; j < m_m; j++)
				{
					wpublicElementB(outStart+i, j) = wpublicElementB(inStart+2*i+1, 0) * psi(0, j);  // B2 * Psi
					for (usint k = 1; k < m_m; k++)
					{
						wpublicElementB(outStart+i, j) += wpublicElementB(inStart+2*i+1, k)* psi(k, j);  // B2 * Psi
					}
				}

				for (usint j = 0; j < m_m; j++)
				{
					wpublicElementB(outStart+i, j) = publicElementB(0, j) - wpublicElementB(outStart+i, j);
				}
			}
		}

		for (usint j = 0; j < m_m; j++)
		{
			(*evalPubElementBf)(0, j) = wpublicElementB(gateCnt-1, j);
		}
	}

	/*
	* Given public parameters, attribute values and ciphertexts corresponding to attributes,
	* computes the ciphertext and the public key Bf for the circuit of attributes
	* m_ell is the number of attributes and the circuit is assumed to be a binary tree of NAND gates
	* Thus, m_ell must be a power of two
	*/
	void KPABE::EvalCT(
			const shared_ptr<ILParams> ilParams,
			const RingMat &pubElementB,
			const usint x[],  // Attributes
			const RingMat &origCT,
			usint *evalAttributes,
			RingMat *evalCT
		)
		{
			// Part pertaining to A (does not change)
			for (usint i = 0; i < m_m; i++)
				(*evalCT)(0, i) = origCT(0, i);

			auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

			usint gateCnt = m_ell - 1;
			RingMat psi(zero_alloc, m_m, m_m); // Needed for Bit Decomposition (BD) matrices

			// w stands for Wire
			RingMat wPublicElementB(zero_alloc, gateCnt, m_m);   // Bis associated with internal wires of the circuit
			RingMat wCT(zero_alloc, gateCnt, m_m);  // Ciphertexts associated with internal wires of the circuit
			usint *wX = new usint[gateCnt]; // Attribute values associated with internal wires of the circuit

			// Temporary variables for bit decomposition operation
			RingMat negB(zero_alloc, 1, m_m);       // EVALUATION (NTT domain)
			std::vector<Poly> digitsC1(m_m);

			// Input level of the circuit
			usint t = m_ell >> 1;  // the number of the gates in the first level (the number of input gates)

			for (usint i = 0; i < t; i++) // looping to evaluate and calculate w, wB, wC and R for all first level input gates
			{
				wX[i] = x[0] - x[2*i+1]*x[2*i+2]; // calculating binary wire value

				for (usint j = 0; j < m_m; j++)     // Negating Bis for bit decomposition
					negB(0, j) = pubElementB(2*i+1, j).Negate();

				polyVec2BalDecom (ilParams, m_base, m_k, negB, &psi);

				/*Starting computation for a NAND circuit*/
				/* x2 * C1 */
				for (usint j = 0; j < m_m; j++) {
					if(x[2*i+2]!=0)
						wCT(i, j) = origCT(2*i+1, j);
					else
						wCT(i, j).SetValuesToZero();
				}

				/* Psi^T*C2 and B2*Psi */
				for (usint j = 0; j < m_m; j++) { // the following two for loops are for vector matrix multiplication (a.k.a B(i+1) * BitDecompose(-Bi) and  gamma (0, 2) (for the second attribute of the circuit) * bitDecompose(-B))
					wPublicElementB(i, j) = pubElementB(2*i+2, 0)*psi(0, j); // B2 * BD(-Bi)
					wCT(i, j) += psi(0, j)*origCT(2*i+2, 0);  // BD(-Bi)*C2
					for (usint k = 1; k < m_m; k++) {
						wPublicElementB(i, j) += pubElementB(2*i+2, k)*psi(k, j);
						wCT(i, j) += psi(k, j)*origCT(2*i+2, k);
					}
				}

				/* B0 - B2*R and C0 - x2*C1 - C2*R */
				for (usint j = 0; j < m_m; j++)
				{
					wPublicElementB(i, j) = pubElementB(0, j) - wPublicElementB(i, j);
					wCT(i, j) = origCT(0, j) - wCT(i, j); // C0 - x2*C1 - R*C2
				}
			}

			/* For internal wires of the circuit.
			 * Depth 0 refers to the circuit level where the input gates are located.
			 * Thus, we start with depth 1
			 */
			usint depth = log2(m_ell);
			for(usint d=1; d<depth; d++)
			{
				usint InStart = m_ell - (m_ell >> (d-1)); // Starting index for the input wires in level d
				usint OutStart = m_ell - (m_ell >> d);    // Starting index for the output wires in level d
				usint gCntinLeveld = m_ell >> (d+1);      // number of gates in level d


				for (usint i = 0; i<gCntinLeveld; i++)
				{
					wX[OutStart+i] = x[0] - wX[InStart+2*i] * wX[InStart+2*i+1];

					for (usint j = 0; j < m_m; j++)
						negB(0, j) = wPublicElementB(InStart+2*i, j).Negate();


					polyVec2BalDecom (ilParams, m_base, m_k, negB, &psi);

					// x2*C1
					for (usint j = 0; j < m_m; j++) {
						if(wX[InStart+2*i+1]!=0)
							wCT(OutStart+i, j) = wCT(InStart+2*i, j);
						else
							wCT(OutStart+i, j).SetValuesToZero();
					}

					for (usint j = 0; j < m_m; j++)
					{
						wPublicElementB(OutStart+i, j) = wPublicElementB(InStart+2*i+1, 0) * psi(0, j);  // B2 * psi
						wCT(OutStart+i, j) += psi(0, j) * wCT(InStart+2*i+1, 0) ; // psi * C2
						for (usint k = 1; k < m_m; k++)
						{
							wPublicElementB(OutStart+i, j) += wPublicElementB(InStart+2*i+1, k)* psi(k, j);  // B2 * psi
							wCT(OutStart+i, j) += psi(k, j) * wCT(InStart+2*i+1, k);  // psi * C2
						}
					}

					for (usint j = 0; j < m_m; j++)
					{
						wPublicElementB(OutStart+i, j) = pubElementB(0, j) - wPublicElementB(OutStart+i, j);
						wCT(OutStart+i, j) = origCT(0, j) - wCT(OutStart+i, j);
					}
				}
			}

			for (usint j = 0; j < m_m; j++)
			{
				(*evalCT)(0, j) = wCT(gateCnt-1, j);
			}

			(*evalAttributes) = wX[gateCnt-1];
		}

	/* The encryption function takes public parameters A, B, and d, attribute values x and the plaintext pt
	 * and generates the ciphertext pair c0 and c1
	 * Note that B is two dimensional array of ring elements (matrix);
	 * Each row corresponds B_i for i = 0, 1, ... ell, where ell is the number of attributes
	 */
	void KPABE::Encrypt(
		shared_ptr<ILParams> ilParams,
		const RingMat &pubElementA,
		const RingMat &pubElementB,
		const Poly &d, //TBA
		const usint x[],
		const Poly &ptext,
		DiscreteGaussianGenerator &dgg, // to generate error terms (Gaussian)
		DiscreteUniformGenerator &dug,  // select according to uniform distribution
		BinaryUniformGenerator &bug,    // select according to uniform distribution binary
		RingMat *ctCin,                   // value set in this function
		Poly *ctC1			            // value set in this function
	)
	{
		// compute c1 first
		Poly s(dug, ilParams, COEFFICIENT);
		s.SwitchFormat();

		Poly qHalf(ilParams, COEFFICIENT, true);
		qHalf += (m_q >> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		Poly err1(ilParams, COEFFICIENT, true); // error term
		err1.SetValues(dgg.GenerateVector(m_N, ilParams->GetModulus()), COEFFICIENT);
		err1.SwitchFormat();

		*ctC1 = s*d + err1 + ptext*qHalf;

		// ***
		// Compute Cin
		auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);
		RingMat g = RingMat(zero_alloc, 1, m_k).GadgetVector(m_base);  // be careful here

		RingMat errA(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), 1, m_m);
		RingMat errCin(zero_alloc, 1, m_m);

		for(usint j=0; j<m_m; j++) {
			(*ctCin)(0, j) = pubElementA(0, j)*s + errA(0, j);
		}
		for(usint i=1; i<m_ell+2; i++) {
			// Si values
			for(usint si=0; si<m_m; si++) {
				errCin(0, si).SetValuesToZero();
				for(usint sj=0; sj<m_m; sj++) {
					if(bug.GenerateInteger() == BigInteger::ONE)
						errCin(0, si) += errA(0, sj);
					else
						errCin(0, si) -= errA(0, sj);
				}
			}

			for(usint j=0; j<m_k; j++) {
				if(x[i-1] != 0)
					(*ctCin)(i, j) = (g(0, j) + pubElementB(i-1, j))*s + errCin(0, j);
				else
					(*ctCin)(i, j) = pubElementB(i-1, j)*s + errCin(0, j);
			}
			(*ctCin)(i, m_m-2) = pubElementB(i-1, m_m-2)*s + errCin(0, m_m-2);
			(*ctCin)(i, m_m-1) = pubElementB(i-1, m_m-1)*s + errCin(0, m_m-1);
		}
	}

	/*
	 * This is method for evaluating a single NAND gate
	 */
	void KPABE::NANDGateEval(
		const shared_ptr<ILParams> ilParams,
		const RingMat &B0,
		const RingMat &C0,
		const usint x[],
		const RingMat &origPubElement,
		const RingMat &origCT,
		usint *evalAttribute,
		RingMat *evalPubElement,
		RingMat *evalCT
	)
	{
		auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

		RingMat psi(zero_alloc, m_m, m_m);

		RingMat negB(zero_alloc, 1, m_m);  			// EVALUATE (NTT domain)
		std::vector<Poly> digitsC1(m_m);

		(*evalAttribute) = 1 - x[0]*x[1];  // Boolean output

		/* -B1 */
		for (usint j = 0; j < m_m; j++)     // Negating B1 for bit decomposition
			negB(0, j) = origPubElement(0, j).Negate();

		polyVec2BalDecom (ilParams, m_base, m_k, negB, &psi);

		/* x2*C1 */
		for (usint i = 0; i < m_m; i++) {
			if(x[1] != 0)
				(*evalCT)(0, i) = origCT(0, i);
			else
				(*evalCT)(0, i).SetValuesToZero();
		}

		/* B2*Psi; Psi*C2 */
		for (usint i = 0; i < m_m; i++) {
			(*evalPubElement)(0, i) = origPubElement(1, 0) * psi(0, i);
			(*evalCT)(0, i) += psi(0, i) * origCT(1, 0);
			for (usint j = 1; j < m_m; j++) {
				(*evalPubElement)(0, i) += origPubElement(1, j) * psi(j, i);
				(*evalCT)(0, i) += psi(j, i) * origCT(1, j);
			}
		}

		for (usint i = 0; i < m_m; i++) {
			(*evalPubElement)(0, i) = B0(0, i) - (*evalPubElement)(0, i);
			(*evalCT)(0, i) = C0(0, i) - (*evalCT)(0, i);
		}
	}

	void KPABE::ANDGateEval(
		shared_ptr<ILParams> ilParams,
		const usint x[],
		const RingMat &origPubElementB,
		const RingMat &origCT,
		usint *evalAttribute,
		RingMat *evalPubElementBf,
		RingMat *evalCT
	)
	{
		auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

		RingMat Psi(zero_alloc, m_m, m_m);

		RingMat negB(zero_alloc, 1, m_m);  			// EVALUATE (NTT domain)
		std::vector<Poly> digitsC1(m_m);

		(*evalAttribute) = x[0]*x[1];  // Boolean output

		/* -B1 */
		for (usint j = 0; j < m_m; j++)     // Negating B1 for bit decomposition
			negB(0, j) = origPubElementB(0, j).Negate();

		polyVec2NAFDecom (ilParams, m_k, negB, &Psi);

		/* x2*C1 */
		for (usint i = 0; i < m_m; i++) {
			if(x[1] != 0)
				(*evalCT)(0, i) = origCT(0, i);
			else
				(*evalCT)(0, i).SetValuesToZero();
		}

		/* B2*Psi; Psi*C2 */
		for (usint i = 0; i < m_m; i++) {
			(*evalPubElementBf)(0, i) = origPubElementB(1, 0) * Psi(0, i);
			(*evalCT)(0, i) += Psi(0, i) * origCT(1, 0);
			for (usint j = 1; j < m_m; j++) {
				(*evalPubElementBf)(0, i) += origPubElementB(1, j) * Psi(j, i);
				(*evalCT)(0, i) += Psi(j, i) * origCT(1, j);
			}
		}
	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
	void KPABE::KeyGen(
		const shared_ptr<ILParams> ilParams,
		const RingMat &pubElementA,               // Public parameter $A \in R_q^{1 \times w}$
		const RingMat &evalPubElementBf,                        // Public parameter $B \in R_q^{ell \times k}$
		const Poly &beta,                     // public key $d \in R_q$
		const RLWETrapdoorPair<Poly> &secElemTA, // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg,          // to generate error terms (Gaussian)
		RingMat *sk                           // Secret key
	)
	{
		RingMat skB(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), m_m, 1);

		Poly newChallenge(ilParams, EVALUATION, true);
		for (usint j = 0; j<m_m; j++)
			newChallenge += (evalPubElementBf(0, j)*skB(j, 0));

		newChallenge = beta - newChallenge;

		double c = 2 * SIGMA;
		double s = SPECTRAL_BOUND(m_N, m_m - 2);
		DiscreteGaussianGenerator dggLargeSigma(sqrt(s * s - c * c));

		RingMat skA(Poly::MakeAllocator(ilParams, EVALUATION), m_m, 1);
		skA = RLWETrapdoorUtility::GaussSamp(m_N, m_k, pubElementA, secElemTA, newChallenge, SIGMA, dgg, dggLargeSigma, m_base);

		for(usint i=0; i<m_m; i++)
			(*sk)(0, i) = skA(i, 0);
		for(usint i=0; i<m_m; i++)
			(*sk)(1, i) = skB(i, 0);
	}

	/*
	 * Decryption function takes the ciphertext pair and the secret keys
	 * and yields the decrypted plaintext in COEFFICIENT form
	 */
	void KPABE::Decrypt(
		const shared_ptr<ILParams> ilParams,
		const RingMat &sk,
		const RingMat &ctA,
		const RingMat &evalCT,
		const Poly &ctC1,
		Poly *dtext
	)
	{
		*dtext = ctA(0, 0)*sk(0, 0);
		for (usint i = 1; i < m_m; i++)
			*dtext += ctA(0, i)*sk(0, i);

		for (usint i = 0; i < m_m; i++)
			*dtext += evalCT(0, i)*sk(1, i);

		*dtext = ctC1 - *dtext;
		dtext->SwitchFormat();

		BigInteger dec, threshold = m_q >> 2, qHalf = m_q >> 1;
		for (usint i = 0; i < m_N; i++)
		{
			dec = dtext->GetValAtIndex(i);

			if (dec > qHalf)
				dec = m_q - dec;
			if (dec > threshold)
				dtext->SetValAtIndex(i, BigInteger::ONE);
			else
				dtext->SetValAtIndex(i, BigInteger::ZERO);
		}

	}


}











