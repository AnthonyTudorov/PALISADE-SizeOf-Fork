/*
 * Abe.cpp
 *
 *  Created on: Mar 23, 2017
 *      Author: savas
 */

#include "KP_ABE.h"

namespace lbcrypto {

	/*
	 * Input: base
	 * Input: vector of (k+2) elements of $R_q$
	 * Input: $k = \lceil \log_(base){q} \rceil$; i.e. the digit length of the modulus + 1 (in base)
	 * Output: matrix of (k+2)x(k+2) elements of $R_2$ where the coefficients are in balanced representation
	 */
	int polyVec2BalDecom (const shared_ptr<ILParams> ilParams, int32_t base, int k, const RingMat &B, RingMat &Psi)
	{
		usint N = ilParams->GetCyclotomicOrder() >> 1;
		usint m = k+2;
		BigInteger q = ilParams->GetModulus();

		auto Big0 = BigInteger::ZERO;
		auto Bigbase = BigInteger(base);
	//	auto Bigbasehalf = BigInteger(base>>1);

		for(usint i=0; i<m; i++)
			for(usint j=0; j<m; j++) {
				Psi(j, i).SetValuesToZero();
				if (Psi(j, i).GetFormat() != COEFFICIENT)
					Psi(j, i).SwitchFormat();
			}

		for (usint ii=0; ii<m; ii++) {
			int digit_i;

			auto tB = B(0, ii);
			if(tB.GetFormat() != COEFFICIENT)
				tB.SwitchFormat();

			for(usint i=0; i<N; i++) {
				auto coeff_i = tB.GetValAtIndex(i);
				int j = 0;
				int flip = 0;
				while(coeff_i > Big0) {
					digit_i = coeff_i.GetDigitAtIndex(1, base);
					if (digit_i > (base>>1)) {
						digit_i = base-digit_i;
#if MATHBACKEND == 7
						coeff_i = coeff_i+base;    // math backend 7
#else //if MATHBACKEND == 2
						coeff_i = coeff_i+Bigbase;    // math backend 2
#endif
						Psi(j, ii).SetValAtIndex(i, q-BigInteger(digit_i));
					}
					else if(digit_i == (base>>1)) {
						if (flip == 0) {
#if MATHBACKEND == 7
							coeff_i = coeff_i+base;  // math backend 7
#else //if MATHBACKEND == 2
							coeff_i = coeff_i+Bigbase;    // math backend 2
#endif
							Psi(j, ii).SetValAtIndex(i, q-BigInteger(digit_i));
						}
						else
							Psi(j, ii).SetValAtIndex(i, BigInteger(digit_i));
						flip = flip ^ 1;
					}
					else
						Psi(j, ii).SetValAtIndex(i, BigInteger(digit_i));

					coeff_i = coeff_i.DividedBy(Bigbase);
					j++;
				}
			}
		}

		Psi.SwitchFormat();

		return 0;
	}

	/*
	 * Input: vector of (k+2) elements of $R_q$
	 * Input: $k = \lceil \log_2{q} \rceil$; i.e. the bit length of the modulus + 1
	 * Output: matrix of (k+2)x(k+2) elements of $R_2$ where the coefficients are in NAF
	 */
	int polyVec2NAFDecom (const shared_ptr<ILParams> ilParams, int k, const RingMat &B, RingMat &Psi)
	{
		usint N = ilParams->GetCyclotomicOrder() >> 1;
		usint m = k+2;
		BigInteger q = ilParams->GetModulus();
		BigInteger q1 = q-BigInteger::ONE;

		auto Big0 = BigInteger::ZERO;
		auto Big1 = BigInteger::ONE;
		auto Big2 = BigInteger::TWO;
		auto Big4 = BigInteger::FOUR;

		for(usint i=0; i<m; i++)
			for(usint j=0; j<m; j++) {
				Psi(j, i).SetValuesToZero();
				if (Psi(j, i).GetFormat() != COEFFICIENT)
					Psi(j, i).SwitchFormat();
			}

		for (usint ii=0; ii<m; ii++) {
			int k_i;

			auto tB = B(0, ii);
			if(tB.GetFormat() != COEFFICIENT)
				tB.SwitchFormat();

			for(usint i=0; i<N; i++) {
				auto coeff_i = tB.GetValAtIndex(i);
				int j = 0;
				while(coeff_i > Big0) {
					k_i = coeff_i.GetBitAtIndex(1);

					if(k_i == 1) {
						k_i = 2 - coeff_i.Mod(Big4).ConvertToInt();
						if(k_i == 1)
							coeff_i = coeff_i - Big1;
						else
							coeff_i = coeff_i + Big1;
					}
					else
						k_i = 0;

					coeff_i = coeff_i.DividedBy(Big2);

					if(k_i == 1)
						Psi(j, ii).SetValAtIndex(i, Big1);
					else if(k_i == -1)
						Psi(j, ii).SetValAtIndex(i, q1);
					else
						Psi(j, ii).SetValAtIndex(i, Big0);
					j++;
				}
			}
		}

		Psi.SwitchFormat();

		return 0;
	}

	/*
	 * This is a setup function for Private Key Generator (PKG);
	 * generates master public key (MPK) and master secret key
	 * m_ell is the number of attributes
	 */
	void KPABE::Setup(
		shared_ptr<ILParams> ilParams,
		int32_t base,
		const usint ell, // number of attributes
		DiscreteUniformGenerator &dug,  // select according to uniform distribution
		RingMat &B
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

		for (usint i = 0; i < B.GetRows(); i++)
			for (usint j = 0; j < B.GetCols(); j++) {
				if(B(i, j).GetFormat() != COEFFICIENT)
					B(i,j).SwitchFormat();
				B(i, j).SetValues(dug.GenerateVector(m_N), COEFFICIENT); // always sample in COEFFICIENT format
				B(i, j).SwitchFormat(); // always kept in EVALUATION format
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
	 * computes the ciphertext and the public key Bf for the circuit of attributes
	 * m_ell is the number of attributes and the circuit is assumed to be a binary tree of NAND gates
	 * Thus, m_ell must be a power of two
	 */
	void KPABE::EvalPK(
		shared_ptr<ILParams> ilParams,
		const RingMat &B,
		RingMat *Bf
	)
	{


		auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

		usint gateCnt = m_ell - 1;

		RingMat Psi(zero_alloc, m_m, m_m); // Needed for bit decomposition matrices
		RingMat wB(zero_alloc, gateCnt, m_m);   // Bis associated with internal wires of the circuit
		// Temporary variables for bit decomposition operation
		RingMat negB(zero_alloc, 1, m_m);       // EVALUATION (NTT domain)
		std::vector<Poly> digitsC1(m_m);

		// Input level of the circuit
		usint t = m_ell >> 1;  // the number of the gates in the first level (the number of input gates)
//pragma omp parallel for /*schedule(dynamic,1)*/ firstprivate(negB, digitsC1)
		for (usint i = 0; i < t; i++) // looping to evaluate and calculate w, wB, wC and R for all first level input gates
		{

			for (usint j = 0; j < m_m; j++)     // Negating Bis for bit decomposition
				negB(0, j) = B(2*i+1, j).Negate();

			//polyVec2NAFDecom (ilParams, m_k, negB, Psi);
			polyVec2BalDecom (ilParams, m_base, m_k, negB, Psi);

			/* Psi^T*C2 and B2*Psi */
			for (usint j = 0; j < m_m; j++) { // the following two for loops are for vector matrix multiplication (a.k.a B(i+1) * BitDecompose(-Bi) and  gamma (0, 2) (for the second attribute of the circuit) * bitDecompose(-B))
				wB(i, j) = B(2*i+2, 0)*Psi(0, j); // B2 * BD(-Bi)
				for (usint k = 1; k < m_m; k++) {
					wB(i, j) += B(2*i+2, k)*Psi(k, j);
				}
			}

			for (usint j = 0; j < m_m; j++)
			{
				wB(i, j) = B(0, j) - wB(i, j);
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

			//#pragma omp parallel for /*schedule(dynamic,1)*/ firstprivate(negB, digitsC1) /*num_threads((number_of_gates + 1)/depthFactor)*/
			for (usint i = 0; i<gCntinLeveld; i++)
			{
				for (usint j = 0; j < m_m; j++)
					negB(0, j) = wB(InStart+2*i, j).Negate();

				polyVec2BalDecom (ilParams, m_base, m_k, negB, Psi);

				for (usint j = 0; j < m_m; j++)
				{
					wB(OutStart+i, j) = wB(InStart+2*i+1, 0) * Psi(0, j);  // B2 * Psi
					for (usint k = 1; k < m_m; k++)
					{
						wB(OutStart+i, j) += wB(InStart+2*i+1, k)* Psi(k, j);  // B2 * Psi
					}
				}

				for (usint j = 0; j < m_m; j++)
				{
					wB(OutStart+i, j) = B(0, j) - wB(OutStart+i, j);
				}
			}
		}

		for (usint j = 0; j < m_m; j++)
		{
			(*Bf)(0, j) = wB(gateCnt-1, j);
		}
	}



	/*
		 * Given public parameters, attribute values and ciphertexts corresponding to attributes,
		 * computes the ciphertext and the public key Bf for the circuit of attributes
		 * m_ell is the number of attributes and the circuit is assumed to be a binary tree of NAND gates
		 * Thus, m_ell must be a power of two
		 */
		void KPABE::EvalCT(
			shared_ptr<ILParams> ilParams,
			const RingMat &B,
			const usint x[],  // Attributes
			const RingMat &Cin,
			usint *y,
			RingMat *Cf
		)
		{
			// Part pertaining to A (does not change)
			for (usint i = 0; i < m_m; i++)
				(*Cf)(0, i) = Cin(0, i);

			auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

			usint gateCnt = m_ell - 1;

			RingMat Psi(zero_alloc, m_m, m_m); // Needed for bit decomposition matrices
			RingMat wB(zero_alloc, gateCnt, m_m);   // Bis associated with internal wires of the circuit
			RingMat wCT(zero_alloc, gateCnt, m_m);  // Ciphertexts associated with internal wires of the circuit
			usint *wX = new usint[gateCnt]; // Attribute values associated with internal wires of the circuit

			// Temporary variables for bit decomposition operation
			RingMat negB(zero_alloc, 1, m_m);       // EVALUATION (NTT domain)
			std::vector<Poly> digitsC1(m_m);

			// Input level of the circuit
			usint t = m_ell >> 1;  // the number of the gates in the first level (the number of input gates)
	//pragma omp parallel for /*schedule(dynamic,1)*/ firstprivate(negB, digitsC1)
			for (usint i = 0; i < t; i++) // looping to evaluate and calculate w, wB, wC and R for all first level input gates
			{
				wX[i] = x[0] - x[2*i+1]*x[2*i+2]; // calculating binary wire value

				for (usint j = 0; j < m_m; j++)     // Negating Bis for bit decomposition
					negB(0, j) = B(2*i+1, j).Negate();

				/*
				 * This was how bit decomposition is previously done
				 * for (int j = 0; j < m_m; j++) { // Performing bit decomposition, first loop is looping over every other Bi (as per the circuit)
					digitsC1 = negB(0, j).BaseDecompose(1); // bit decomposing each polynomial in Bi, BitDecompose already gives you a vector based on least significant bit order
					for (int k = 0; k < m_k; k++)  // Moving the decomposed polynomial into jth column of R
						Psi(k, j) = digitsC1[k];
					Psi(m_m-2, j).SetValuesToZero();
					Psi(m_m-1, j).SetValuesToZero();
				}
				*/
				//polyVec2NAFDecom (ilParams, m_k, negB, Psi);
				polyVec2BalDecom (ilParams, m_base, m_k, negB, Psi);

				/*Starting computation for a NAND circuit*/
				/* x2 * C1 */
				for (usint j = 0; j < m_m; j++) {
					if(x[2*i+2]!=0)
						wCT(i, j) = Cin(2*i+1, j);
					else
						wCT(i, j).SetValuesToZero();
				}

				/* Psi^T*C2 and B2*Psi */
				for (usint j = 0; j < m_m; j++) { // the following two for loops are for vector matrix multiplication (a.k.a B(i+1) * BitDecompose(-Bi) and  gamma (0, 2) (for the second attribute of the circuit) * bitDecompose(-B))
					wB(i, j) = B(2*i+2, 0)*Psi(0, j); // B2 * BD(-Bi)
					wCT(i, j) += Psi(0, j)*Cin(2*i+2, 0);  // BD(-Bi)*C2
					for (usint k = 1; k < m_m; k++) {
						wB(i, j) += B(2*i+2, k)*Psi(k, j);
						wCT(i, j) += Psi(k, j)*Cin(2*i+2, k);
					}
				}

				/* B0 - B2*R and C0 - x2*C1 - C2*R */
				for (usint j = 0; j < m_m; j++)
				{
					wB(i, j) = B(0, j) - wB(i, j);
					wCT(i, j) = Cin(0, j) - wCT(i, j); // C0 - x2*C1 - R*C2
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

				/*std::cout << "Level: " << d << std::endl;
				std::cout << "InStart: " << InStart << std::endl;
				std::cout << "OutStart: " << OutStart << std::endl;
				std::cout << "No of gates in the level: " << gCntinLeveld << std::endl;*/

				//#pragma omp parallel for /*schedule(dynamic,1)*/ firstprivate(negB, digitsC1) /*num_threads((number_of_gates + 1)/depthFactor)*/
				for (usint i = 0; i<gCntinLeveld; i++)
				{
					wX[OutStart+i] = x[0] - wX[InStart+2*i] * wX[InStart+2*i+1];

					for (usint j = 0; j < m_m; j++)
						negB(0, j) = wB(InStart+2*i, j).Negate();

					/*
					 * * This was how bit decomposition is previously done
					for (int j = 0; j < m_m; j++)
					{
						digitsC1 = negB(0, j).BaseDecompose(1);
						for (int k = 0; k < m_k; k++)
							Psi(k, j) = digitsC1[k];
						Psi(m_m-2, j).SetValuesToZero();
						Psi(m_m-1, j).SetValuesToZero();
					}
					*
					*/
					//polyVec2NAFDecom (ilParams, m_k, negB, Psi);
					polyVec2BalDecom (ilParams, m_base, m_k, negB, Psi);

					// x2*C1
					for (usint j = 0; j < m_m; j++) {
						if(wX[InStart+2*i+1]!=0)
							wCT(OutStart+i, j) = wCT(InStart+2*i, j);
						else
							wCT(OutStart+i, j).SetValuesToZero();
					}

					for (usint j = 0; j < m_m; j++)
					{
						wB(OutStart+i, j) = wB(InStart+2*i+1, 0) * Psi(0, j);  // B2 * Psi
						wCT(OutStart+i, j) += Psi(0, j) * wCT(InStart+2*i+1, 0) ; // Psi * C2
						for (usint k = 1; k < m_m; k++)
						{
							wB(OutStart+i, j) += wB(InStart+2*i+1, k)* Psi(k, j);  // B2 * Psi
							wCT(OutStart+i, j) += Psi(k, j) * wCT(InStart+2*i+1, k);  // Psi * C2
						}
					}

					for (usint j = 0; j < m_m; j++)
					{
						wB(OutStart+i, j) = B(0, j) - wB(OutStart+i, j);
						wCT(OutStart+i, j) = Cin(0, j) - wCT(OutStart+i, j);
					}
				}
			}

			for (usint j = 0; j < m_m; j++)
			{
				(*Cf)(0, j) = wCT(gateCnt-1, j);
			}

			(*y) = wX[gateCnt-1];
		}

	/* The encryption function takes public parameters A, B, and d, attribute values x and the plaintext pt
	 * and generates the ciphertext pair c0 and c1
	 * Note that B is two dimensional array of ring elements (matrix);
	 * Each row corresponds B_i for i = 0, 1, ... ell, where ell is the number of attributes
	 */
	void KPABE::Encrypt(
		shared_ptr<ILParams> ilParams,
		const RingMat &A,
		const RingMat &B,
		const Poly &d,
		const usint x[],
		const Poly &ptext,
		DiscreteGaussianGenerator &dgg, // to generate error terms (Gaussian)
		DiscreteUniformGenerator &dug,  // select according to uniform distribution
		BinaryUniformGenerator &bug,    // select according to uniform distribution binary
		RingMat &Cin,                   // value set in this function
		Poly &c1			            // value set in this function
	)
	{
		// ***
		// compute c1 first
		Poly s(dug, ilParams, COEFFICIENT);
		s.SwitchFormat();
		// s = 1 for debugging; remove the following two lines after the fix
		//s.SetValuesToZero();
		//s.AddILElementOne();

		Poly qHalf(ilParams, COEFFICIENT, true);
		qHalf += (m_q >> 1);
		qHalf.SwitchFormat();
		qHalf.AddILElementOne();

		Poly err1(ilParams, COEFFICIENT, true); // error term
		err1.SetValues(dgg.GenerateVector(m_N, ilParams->GetModulus()), COEFFICIENT);
		err1.SwitchFormat();

		c1 = s*d + err1 + ptext*qHalf;

		// ***
		// Compute Cin
		auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);
		RingMat G = RingMat(zero_alloc, 1, m_k).GadgetVector(m_base);  // be careful here

		RingMat errA(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), 1, m_m);
		RingMat errCin(zero_alloc, 1, m_m);

		for(usint j=0; j<m_m; j++) {
			Cin(0, j) = A(0, j)*s + errA(0, j);
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
				//if(i == 1)
					//Cin(i, j) = (G(0, j) + B(i-1, j))*s + errBi(0, j);
				if(x[i-1] != 0)
					Cin(i, j) = (G(0, j) + B(i-1, j))*s + errCin(0, j);
				else
					Cin(i, j) = B(i-1, j)*s + errCin(0, j);
			}
			Cin(i, m_m-2) = B(i-1, m_m-2)*s + errCin(0, m_m-2);
			Cin(i, m_m-1) = B(i-1, m_m-1)*s + errCin(0, m_m-1);
		}
	}

	/*
	 * This is method for evaluating a single NAND gate
	 */
	void KPABE::NANDGateEval(
		shared_ptr<ILParams> ilParams,
		const RingMat &B0,
		const RingMat &C0,
		const usint x[],
		const RingMat &B,
		const RingMat &C,
		usint *y,
		RingMat *Bf,
		RingMat *Cf
	)
	{
		auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

		RingMat Psi(zero_alloc, m_m, m_m);

		RingMat negB(zero_alloc, 1, m_m);  			// EVALUATE (NTT domain)
		std::vector<Poly> digitsC1(m_m);

		(*y) = 1 - x[0]*x[1];  // Boolean output

		/* -B1 */
		for (usint j = 0; j < m_m; j++)     // Negating B1 for bit decomposition
			negB(0, j) = B(0, j).Negate();

		/* Psi = BD(-B1) */
		/* This is how it is done before binary NAF decomposition
		 * for (int j = 0; j < m_m; j++) { // Performing bit decomposition, first loop is looping over every other Bi (as per the circuit)
			digitsC1 = negB(0, j).BaseDecompose(1); // bit decomposing each polynomial in Bi, BitDecompose already gives you a vector based on least significant bit order
			for (int k = 0; k < m_k; k++)  // Moving the decomposed polynomial into jth column of R
				Psi(k, j) = digitsC1[k];
			Psi(m_m-2, j).SetValuesToZero();
			Psi(m_m-1, j).SetValuesToZero();
		}
		*/
		//polyVec2NAFDecom (ilParams, m_k, negB, Psi);
		polyVec2BalDecom (ilParams, m_base, m_k, negB, Psi);

		/* x2*C1 */
		for (usint i = 0; i < m_m; i++) {
			if(x[1] != 0)
				(*Cf)(0, i) = C(0, i);
			else
				(*Cf)(0, i).SetValuesToZero();
		}

		/* B2*Psi; Psi*C2 */
		for (usint i = 0; i < m_m; i++) {
			(*Bf)(0, i) = B(1, 0) * Psi(0, i);
			(*Cf)(0, i) += Psi(0, i) * C(1, 0);
			for (usint j = 1; j < m_m; j++) {
				(*Bf)(0, i) += B(1, j) * Psi(j, i);
				(*Cf)(0, i) += Psi(j, i) * C(1, j);
			}
		}

		/* Cf = C0 - x2*C1 - C2*Psi
		 * Bf = B0 - B2*Psi */
		for (usint i = 0; i < m_m; i++) {
			(*Bf)(0, i) = B0(0, i) - (*Bf)(0, i);
			(*Cf)(0, i) = C0(0, i) - (*Cf)(0, i);
		}
	}

	void KPABE::ANDGateEval(
		shared_ptr<ILParams> ilParams,
		const usint x[],
		const RingMat &B,
		const RingMat &C,
		usint *y,
		RingMat *Bf,
		RingMat *Cf
	)
	{
		auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

		RingMat Psi(zero_alloc, m_m, m_m);

		RingMat negB(zero_alloc, 1, m_m);  			// EVALUATE (NTT domain)
		std::vector<Poly> digitsC1(m_m);

		(*y) = x[0]*x[1];  // Boolean output

		/* -B1 */
		for (usint j = 0; j < m_m; j++)     // Negating B1 for bit decomposition
			negB(0, j) = B(0, j).Negate();

		/* Psi = BD(-B1) */
		/* This is how it is done before binary NAF decomposition
		for (int j = 0; j < m_m; j++) { // Performing bit decomposition, first loop is looping over every other Bi (as per the circuit)
			digitsC1 = negB(0, j).BaseDecompose(1); // bit decomposing each polynomial in Bi, BitDecompose already gives you a vector based on least significant bit order
			for (int k = 0; k < m_k; k++)  // Moving the decomposed polynomial into jth column of R
				Psi(k, j) = digitsC1[k];
			Psi(m_m-2, j).SetValuesToZero();
			Psi(m_m-1, j).SetValuesToZero();
		}
		*/
		polyVec2NAFDecom (ilParams, m_k, negB, Psi);

		/* x2*C1 */
		for (usint i = 0; i < m_m; i++) {
			if(x[1] != 0)
				(*Cf)(0, i) = C(0, i);
			else
				(*Cf)(0, i).SetValuesToZero();
		}

		/* B2*Psi; Psi*C2 */
		for (usint i = 0; i < m_m; i++) {
			(*Bf)(0, i) = B(1, 0) * Psi(0, i);
			(*Cf)(0, i) += Psi(0, i) * C(1, 0);
			for (usint j = 1; j < m_m; j++) {
				(*Bf)(0, i) += B(1, j) * Psi(j, i);
				(*Cf)(0, i) += Psi(j, i) * C(1, j);
			}
		}
	}

	/* Given public parameter d and a public key B,
	it generates the corresponding secret key: skA for A and skB for B */
	/* Note that only PKG can call this fcuntion as it needs the trapdoor T_A */
	void KPABE::KeyGen(
		const shared_ptr<ILParams> ilParams,
		const RingMat &A,                        // Public parameter $A \in R_q^{1 \times w}$
		const RingMat &Bf,                        // Public parameter $B \in R_q^{ell \times k}$
		const Poly &beta,                     // public key $d \in R_q$
		const RLWETrapdoorPair<Poly> &T_A, // Secret parameter $T_H \in R_q^{1 \times k} \times R_q^{1 \times k}$
		DiscreteGaussianGenerator &dgg,          // to generate error terms (Gaussian)
		RingMat &sKey                           // Secret key
	)
	{
		RingMat skB(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), m_m, 1);

		Poly newChallenge(ilParams, EVALUATION, true);
		for (usint j = 0; j<m_m; j++)
			newChallenge += (Bf(0, j)*skB(j, 0));

		newChallenge = beta - newChallenge;

		double c = 2 * SIGMA;
		double s = SPECTRAL_BOUND(m_N, m_m - 2);
		DiscreteGaussianGenerator dggLargeSigma(sqrt(s * s - c * c));

		RingMat skA(Poly::MakeAllocator(ilParams, EVALUATION), m_m, 1);
		//skA = RLWETrapdoorUtility::GaussSamp(m_N, m_k, A, T_A, newChallenge, SIGMA, 2, dgg, dggLargeSigma);
		skA = RLWETrapdoorUtility::GaussSamp(m_N, m_k, A, T_A, newChallenge, m_base, SIGMA, dgg, dggLargeSigma);

		for(usint i=0; i<m_m; i++)
			sKey(0, i) = skA(i, 0);
		for(usint i=0; i<m_m; i++)
			sKey(1, i) = skB(i, 0);
	}

	/*
	 * Decryption function takes the ciphertext pair and the secret keys
	 * and yields the decrypted plaintext in COEFFICIENT form
	 */
	void KPABE::Decrypt(
		const shared_ptr<ILParams> ilParams,
		const RingMat &sKey,
		const RingMat &CA,
		const RingMat &Cf,
		const Poly &c1,
		Poly &dtext
	)
	{
		dtext = CA(0, 0)*sKey(0, 0);
		for (usint i = 1; i < m_m; i++)
			dtext += CA(0, i)*sKey(0, i);

		for (usint i = 0; i < m_m; i++)
			dtext += Cf(0, i)*sKey(1, i);

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

	/*
		 * Given public parameters, attribute values and ciphertexts corresponding to attributes,
		 * computes the ciphertext and the public key Bf for the circuit of attributes
		 * m_ell is the number of attributes and the circuit is assumed to be a binary tree of NAND gates
		 * Thus, m_ell must be a power of two
		 */
		void KPABE::EvalPKDeprecated(
			shared_ptr<ILParams> ilParams,
			const RingMat &B,
			const usint x[],  // Attributes
			const RingMat &Cin,
			usint *y,
			RingMat *Bf,
			RingMat *Cf
		)
		{
			// Part pertaining to A (does not change)
			for (usint i = 0; i < m_m; i++)
				(*Cf)(0, i) = Cin(0, i);

			auto zero_alloc = Poly::MakeAllocator(ilParams, EVALUATION);

			usint gateCnt = m_ell - 1;

			RingMat Psi(zero_alloc, m_m, m_m); // Needed for bit decomposition matrices
			RingMat wB(zero_alloc, gateCnt, m_m);   // Bis associated with internal wires of the circuit
			RingMat wCT(zero_alloc, gateCnt, m_m);  // Ciphertexts associated with internal wires of the circuit
			usint *wX = new usint[gateCnt]; // Attribute values associated with internal wires of the circuit

			// Temporary variables for bit decomposition operation
			RingMat negB(zero_alloc, 1, m_m);       // EVALUATION (NTT domain)
			std::vector<Poly> digitsC1(m_m);

			// Input level of the circuit
			usint t = m_ell >> 1;  // the number of the gates in the first level (the number of input gates)
	//pragma omp parallel for /*schedule(dynamic,1)*/ firstprivate(negB, digitsC1)
			for (usint i = 0; i < t; i++) // looping to evaluate and calculate w, wB, wC and R for all first level input gates
			{
				wX[i] = x[0] - x[2*i+1]*x[2*i+2]; // calculating binary wire value

				for (usint j = 0; j < m_m; j++)     // Negating Bis for bit decomposition
					negB(0, j) = B(2*i+1, j).Negate();

				/*
				 * This was how bit decomposition is previously done
				 * for (int j = 0; j < m_m; j++) { // Performing bit decomposition, first loop is looping over every other Bi (as per the circuit)
					digitsC1 = negB(0, j).BaseDecompose(1); // bit decomposing each polynomial in Bi, BitDecompose already gives you a vector based on least significant bit order
					for (int k = 0; k < m_k; k++)  // Moving the decomposed polynomial into jth column of R
						Psi(k, j) = digitsC1[k];
					Psi(m_m-2, j).SetValuesToZero();
					Psi(m_m-1, j).SetValuesToZero();
				}
				*/
				//polyVec2NAFDecom (ilParams, m_k, negB, Psi);
				polyVec2BalDecom (ilParams, m_base, m_k, negB, Psi);

				/*Starting computation for a NAND circuit*/
				/* x2 * C1 */
				for (usint j = 0; j < m_m; j++) {
					if(x[2*i+2]!=0)
						wCT(i, j) = Cin(2*i+1, j);
					else
						wCT(i, j).SetValuesToZero();
				}

				/* Psi^T*C2 and B2*Psi */
				for (usint j = 0; j < m_m; j++) { // the following two for loops are for vector matrix multiplication (a.k.a B(i+1) * BitDecompose(-Bi) and  gamma (0, 2) (for the second attribute of the circuit) * bitDecompose(-B))
					wB(i, j) = B(2*i+2, 0)*Psi(0, j); // B2 * BD(-Bi)
					wCT(i, j) += Psi(0, j)*Cin(2*i+2, 0);  // BD(-Bi)*C2
					for (usint k = 1; k < m_m; k++) {
						wB(i, j) += B(2*i+2, k)*Psi(k, j);
						wCT(i, j) += Psi(k, j)*Cin(2*i+2, k);
					}
				}

				/* B0 - B2*R and C0 - x2*C1 - C2*R */
				for (usint j = 0; j < m_m; j++)
				{
					wB(i, j) = B(0, j) - wB(i, j);
					wCT(i, j) = Cin(0, j) - wCT(i, j); // C0 - x2*C1 - R*C2
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

				/*std::cout << "Level: " << d << std::endl;
				std::cout << "InStart: " << InStart << std::endl;
				std::cout << "OutStart: " << OutStart << std::endl;
				std::cout << "No of gates in the level: " << gCntinLeveld << std::endl;*/

				//#pragma omp parallel for /*schedule(dynamic,1)*/ firstprivate(negB, digitsC1) /*num_threads((number_of_gates + 1)/depthFactor)*/
				for (usint i = 0; i<gCntinLeveld; i++)
				{
					wX[OutStart+i] = x[0] - wX[InStart+2*i] * wX[InStart+2*i+1];

					for (usint j = 0; j < m_m; j++)
						negB(0, j) = wB(InStart+2*i, j).Negate();

					/*
					 * * This was how bit decomposition is previously done
					for (int j = 0; j < m_m; j++)
					{
						digitsC1 = negB(0, j).BaseDecompose(1);
						for (int k = 0; k < m_k; k++)
							Psi(k, j) = digitsC1[k];
						Psi(m_m-2, j).SetValuesToZero();
						Psi(m_m-1, j).SetValuesToZero();
					}
					*
					*/
					//polyVec2NAFDecom (ilParams, m_k, negB, Psi);
					polyVec2BalDecom (ilParams, m_base, m_k, negB, Psi);

					// x2*C1
					for (usint j = 0; j < m_m; j++) {
						if(wX[InStart+2*i+1]!=0)
							wCT(OutStart+i, j) = wCT(InStart+2*i, j);
						else
							wCT(OutStart+i, j).SetValuesToZero();
					}

					for (usint j = 0; j < m_m; j++)
					{
						wB(OutStart+i, j) = wB(InStart+2*i+1, 0) * Psi(0, j);  // B2 * Psi
						wCT(OutStart+i, j) += Psi(0, j) * wCT(InStart+2*i+1, 0) ; // Psi * C2
						for (usint k = 1; k < m_m; k++)
						{
							wB(OutStart+i, j) += wB(InStart+2*i+1, k)* Psi(k, j);  // B2 * Psi
							wCT(OutStart+i, j) += Psi(k, j) * wCT(InStart+2*i+1, k);  // Psi * C2
						}
					}

					for (usint j = 0; j < m_m; j++)
					{
						wB(OutStart+i, j) = B(0, j) - wB(OutStart+i, j);
						wCT(OutStart+i, j) = Cin(0, j) - wCT(OutStart+i, j);
					}
				}
			}

			for (usint j = 0; j < m_m; j++)
			{
				(*Bf)(0, j) = wB(gateCnt-1, j);
				(*Cf)(0, j) = wCT(gateCnt-1, j);
			}

			(*y) = wX[gateCnt-1];
		}
}











