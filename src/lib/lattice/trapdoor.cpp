/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: 
*		Dr. Yuriy Polyakov, <polyakov@njit.edu>
*		Kevin King, kcking@mit.edu
* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2016, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONT0RIBUTORS "AS IS" AND
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
* This code provides the utility for working with trapdoor lattices.
*/

#include "../crypto/cryptocontext.h"
#include "trapdoor.h"

namespace lbcrypto {

	//Trapdoor generation method as described in section 3.2 of https://eprint.iacr.org/2013/297.pdf (Construction 1)
	std::pair<RingMat, RLWETrapdoorPair<ILVector2n>> RLWETrapdoorUtility::TrapdoorGen(shared_ptr<ILParams> params, int stddev)
	{
		auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
		auto gaussian_alloc = ILVector2n::MakeDiscreteGaussianCoefficientAllocator(params, EVALUATION, stddev);
		auto uniform_alloc = ILVector2n::MakeDiscreteUniformAllocator(params, EVALUATION);
		size_t n = params->GetCyclotomicOrder() / 2;
		//  k ~= bitlength of q
		// size_t k = params.GetModulus().GetMSB();
		double val = params->GetModulus().ConvertToDouble();
		//std::cout << "val : " << val << std::endl;
		double logTwo = log(val-1.0)/log(2)+1.0;
		//std::cout << "logTwo : " << logTwo << std::endl;
		size_t k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();
		//std::cout << "BitLength in Trapdoor: " << k << std::endl;

		auto a = uniform_alloc();

		RingMat r(zero_alloc, 1, k, gaussian_alloc);
		RingMat e(zero_alloc, 1, k, gaussian_alloc);

		RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();

		RingMat A(zero_alloc, 1, k+2);
		A(0,0) = 1;
		A(0,1) = *a;
		for (size_t i = 0; i < k; ++i) {
			A(0, i+2) = g(0, i) - (*a*r(0, i) + e(0, i));
		}

		return std::pair<RingMat, RLWETrapdoorPair<ILVector2n>>(A, RLWETrapdoorPair<ILVector2n>(r, e));

	}

	// Gaussian sampling introduced in https://eprint.iacr.org/2011/501.pdf and described 
	// in a simple manner in https://eprint.iacr.org/2013/297.pdf

	RingMat RLWETrapdoorUtility::GaussSamp(size_t n, size_t k, const RingMat& A, const RLWETrapdoorPair<ILVector2n>& T, const Matrix<LargeFloat> &SigmaP, const ILVector2n &u,
			double sigma, DiscreteGaussianGenerator &dgg) {

		const shared_ptr<ILParams> params = u.GetParams();
		auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

		//We should convert this to a static variable later
		int32_t c(ceil(2 * sqrt(log(2*n*(1 + 1/4e-22)) / M_PI)));

		const BigBinaryInteger& modulus = A(0,0).GetModulus();

		Matrix<int32_t> p([](){ return make_unique<int32_t>(); }, (2+k)*n, 1);
		LatticeGaussSampUtility::NonSphericalSample(n, SigmaP, c, &p);

		//std::cout << "GaussSamp: Just finished running NonSphericalSample" << std::endl;

		// pHat is in the coefficient representation
		Matrix<ILVector2n> pHat = SplitInt32IntoILVector2nElements(p,n,params);

		// Now pHat is in the evaluation representation
		pHat.SwitchFormat();

		//std::cout<<"phat dimensions: rows, columns" << pHat.GetRows() << pHat.GetCols() << std::endl;

		// YSP It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension of (k + 2) x 1
		// perturbedSyndrome is in the evaluation representation
		ILVector2n perturbedSyndrome = u - (A.Mult(pHat))(0, 0);

		//Matrix<BigBinaryInteger> zHatBBI(BigBinaryInteger::Allocator, k, n);
		Matrix<int32_t> zHatBBI([](){ return make_unique<int32_t>(); },  k, n);

		// GaussSampG(perturbedSyndrome,sigma,k,dgg,&zHatBBI);

		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();

		//LatticeGaussSampUtility::GaussSampGq(perturbedSyndrome,sigma,k,modulus,dgg,&zHatBBI);
		LatticeGaussSampUtility::GaussSampGqV2(perturbedSyndrome, sigma, k, modulus, 2, dgg, &zHatBBI);


		// Convert zHat from a matrix of BBI to a vector of ILVector2n ring elements
		// zHat is in the coefficient representation
		RingMat zHat = SplitInt32AltIntoILVector2nElements(zHatBBI,n,params);
		// Now converting it to the evaluation representation before multiplication
		zHat.SwitchFormat();

		RingMat zHatPrime(zero_alloc, k + 2, 1);

		zHatPrime(0,0) = pHat(0,0) + T.m_e.Mult(zHat)(0,0);
		zHatPrime(1,0) = pHat(1,0) + T.m_r.Mult(zHat)(0,0);

		for (size_t row = 2; row < k + 2; ++row)
			zHatPrime(row, 0) = pHat(row, 0) + zHat(row - 2, 0);

		/*
		
		//This code is helpful in tightening parameter constraints

		zHatPrime(0, 0).SwitchFormat();
		ILVector2n z0 = zHatPrime(0, 0);
		zHatPrime(0, 0).SwitchFormat();

		zHatPrime(1, 0).SwitchFormat();
		ILVector2n z1 = zHatPrime(1, 0);
		zHatPrime(1, 0).SwitchFormat();

		std::cout << "z0=" << z0.Norm() << std::endl;
		std::cout << "z1=" << z1.Norm() << std::endl;

		zHatPrime(2, 0).SwitchFormat();
		ILVector2n z2 = zHatPrime(2, 0);
		zHatPrime(2, 0).SwitchFormat();

		std::cout << "z2=" << z2.Norm() << std::endl;

		pHat(2, 0).SwitchFormat();
		ILVector2n pHat2 = pHat(2, 0);
		pHat(2, 0).SwitchFormat();

		std::cout << "pHat=" << pHat2.Norm() << std::endl;
	
		zHat(0, 0).SwitchFormat();
		ILVector2n zHat2 = zHat(0, 0);
		zHat(0, 0).SwitchFormat();

		std::cout << "zHat=" << zHat2.Norm() << std::endl;
		
		*/

		return zHatPrime;

	}

	// Gaussian sampling based on the UCSD integer perturbation sampling

	RingMat RLWETrapdoorUtility::GaussSampV3(size_t n, size_t k, const RingMat& A, 
		const RLWETrapdoorPair<ILVector2n>& T, const ILVector2n &u,
		double sigma, DiscreteGaussianGenerator &dgg) {

		const shared_ptr<ILParams> params = u.GetParams();
		auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

		//We should convert this to a static variable later
		int32_t c(ceil(2 * sqrt(log(2 * n*(1 + 1 / 4e-22)) / M_PI)));
		int32_t a(floor(c / 2));

		const BigBinaryInteger& modulus = A(0, 0).GetModulus();

		Matrix<int32_t> p([]() { return make_unique<int32_t>(); }, (2 + k)*n, 1);

		//spectral bound s
		double s = 40 * std::sqrt(n*(k + 2));

		ZSampleSigmaP(n, s, a, T, &p, dgg);

		//LatticeGaussSampUtility::NonSphericalSample(n, SigmaP, c, &p);

		//std::cout << "GaussSamp: Just finished running NonSphericalSample" << std::endl;

		// pHat is in the coefficient representation
		Matrix<ILVector2n> pHat = SplitInt32IntoILVector2nElements(p, n, params);

		// Now pHat is in the evaluation representation
		pHat.SwitchFormat();

		//std::cout<<"phat dimensions: rows, columns" << pHat.GetRows() << pHat.GetCols() << std::endl;

		// YSP It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension of (k + 2) x 1
		// perturbedSyndrome is in the evaluation representation
		ILVector2n perturbedSyndrome = u - (A.Mult(pHat))(0, 0);

		//Matrix<BigBinaryInteger> zHatBBI(BigBinaryInteger::Allocator, k, n);
		Matrix<int32_t> zHatBBI([]() { return make_unique<int32_t>(); }, k, n);

		// GaussSampG(perturbedSyndrome,sigma,k,dgg,&zHatBBI);

		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();

		//LatticeGaussSampUtility::GaussSampGq(perturbedSyndrome,sigma,k,modulus,dgg,&zHatBBI);
		LatticeGaussSampUtility::GaussSampGqV2(perturbedSyndrome, sigma, k, modulus, 2, dgg, &zHatBBI);

		// Convert zHat from a matrix of BBI to a vector of ILVector2n ring elements
		// zHat is in the coefficient representation
		RingMat zHat = SplitInt32AltIntoILVector2nElements(zHatBBI, n, params);
		// Now converting it to the evaluation representation before multiplication
		zHat.SwitchFormat();

		RingMat zHatPrime(zero_alloc, k + 2, 1);

		zHatPrime(0, 0) = pHat(0, 0) + T.m_e.Mult(zHat)(0, 0);
		zHatPrime(1, 0) = pHat(1, 0) + T.m_r.Mult(zHat)(0, 0);

		for (size_t row = 2; row < k + 2; ++row)
			zHatPrime(row, 0) = pHat(row, 0) + zHat(row - 2, 0);

	
		return zHatPrime;

	}

	// Generation of perturbation matrix based on Cholesky decomposition 
	// see Section 3.2 of https://eprint.iacr.org/2013/297.pdf for details

	void RLWETrapdoorUtility::PerturbationMatrixGen(size_t n, size_t k, const RingMat& A, 
		const RLWETrapdoorPair<ILVector2n>& T, double s, Matrix<LargeFloat> *sigmaSqrt) {
		TimeVar t1; // for TIC TOC
		bool dbg_flag = 0; //set to 1 for debug timing...
		//We should convert this to a static variable later
		int32_t c(ceil(2 * sqrt(log(2*n*(1 + 1/4e-22)) / M_PI)));

		const BigBinaryInteger& modulus = A(0,0).GetModulus();

		//Computing e and r in coefficient representation
		Matrix<ILVector2n> eCoeff = T.m_e;
		eCoeff.SwitchFormat();
		Matrix<ILVector2n> rCoeff = T.m_r;
		rCoeff.SwitchFormat();

		TIC(t1);
		Matrix<BigBinaryInteger> R = Rotate(eCoeff)
										.VStack(Rotate(rCoeff))
										.VStack(Matrix<BigBinaryInteger>(BigBinaryInteger::Allocator, n*k, n*k).Identity());
		DEBUG("p1: "<<TOC(t1) <<" ms");
		TIC(t1);
	Matrix<int32_t> Rint = ConvertToInt32(R, modulus);
		DEBUG("P2: "<<TOC(t1) <<" ms");
		TIC(t1);
		Matrix<int32_t> COV = Rint*Rint.Transpose().ScalarMult(c*c);
		DEBUG("P3: "<<TOC(t1) <<" ms");
		TIC(t1);
		Matrix<int32_t> SigmaP = Matrix<int32_t>([](){ return make_unique<int32_t>(); }, COV.GetRows(), COV.GetCols()).Identity().ScalarMult(s*s) - COV;
		DEBUG("P4: "<<TOC(t1) <<" ms");
		TIC(t1);
		Matrix<int32_t> p([](){ return make_unique<int32_t>(); }, (2+k)*n, 1);
		DEBUG("P5: "<<TOC(t1) <<" ms");
		TIC(t1);
		int32_t a(floor(c/2));

		// YSP added the a^2*I term which was missing in the original LaTex document
		Matrix<int32_t> sigmaA = SigmaP - (a*a)*Matrix<int32_t>(SigmaP.GetAllocator(), SigmaP.GetRows(), SigmaP.GetCols()).Identity();
		DEBUG("P6: "<<TOC(t1) <<" ms");
		TIC(t1);
		*sigmaSqrt = Cholesky(sigmaA);
		DEBUG("P7: "<<TOC(t1) <<" ms");
	}
	
	
	//Alternate method for generation of perturbation matrix based on Cholesky decomposition
	// see Section 3.2 of https ://eprint.iacr.org/2013/297.pdf for base implementation, Section 4.4 for improvements
	void RLWETrapdoorUtility::PerturbationMatrixGenAlt(size_t n,size_t k,const RingMat& A,
		const RLWETrapdoorPair<ILVector2n>& T, double s, Matrix<LargeFloat> *sigmaSqrt) {

		int32_t r(ceil(2 * sqrt(log(2 * n*(1 + 1 / 4e-22)) / M_PI)));
		int32_t a(floor(r / 2));
		const BigBinaryInteger& modulus = A(0, 0).GetModulus();
		
		Matrix<ILVector2n> eCoeff = T.m_e;
		eCoeff.SwitchFormat();
		Matrix<ILVector2n> rCoeff = T.m_r;
		rCoeff.SwitchFormat();
		Matrix<BigBinaryInteger> R = Rotate(eCoeff).VStack(Rotate(rCoeff));


		Matrix<int32_t> Rint = ConvertToInt32(R, modulus);
		int32_t b = s*s - 5 *a *a;
		Matrix<int32_t> Snk = ((int32_t)(s*s - a*a))*(Matrix<int32_t>(Rint.GetAllocator(), n * 2, n * 2).Identity())- Rint*Rint.Transpose().ScalarMult(double(r*r + 1 / b));
		*sigmaSqrt = Cholesky(Snk); 
	}

	void RLWETrapdoorUtility::ZSampleSigmaP(size_t n, double s, double sigma,
		const RLWETrapdoorPair<ILVector2n>& Tprime, Matrix<int32_t> *perturbationVector, const DiscreteGaussianGenerator & dgg) {

		Matrix<ILVector2n> Tprime0 = Tprime.m_e;
		Matrix<ILVector2n> Tprime1 = Tprime.m_r;
		Matrix<ILVector2n> TprimeTransposed0 = Tprime0.Transpose();
		Matrix<ILVector2n> TprimeTransposed1 = Tprime1.Transpose();

		//Perform multiplication in the NTT format
		ILVector2n va = (Tprime0 * TprimeTransposed0)(0, 0);
		ILVector2n vb = (Tprime1 * TprimeTransposed0)(0, 0);
		ILVector2n vd = (Tprime1 * TprimeTransposed1)(0, 0);

		//Switch the ring elements (polynomials) to coefficient representation
		va.SwitchFormat();
		vb.SwitchFormat();
		vd.SwitchFormat();

		//Create field elements from ring elements
		Field2n a(va), b(vb), d(vd);

		a = a.ScalarMult(s * s * (1 - sigma * sigma / (s * s - sigma * sigma)));
		b = b.ScalarMult(-s *s * sigma * sigma / (s* s - sigma * sigma));
		d = d.ScalarMult(s * s * (1 - sigma * sigma / (s * s - sigma * sigma)));

		//converts the field elements to DFT representation
		a.SwitchFormat();
		b.SwitchFormat();
		d.SwitchFormat();

		size_t k = Tprime0.GetRows();
		Matrix<int32_t> p2ZVector([]() { return make_unique<int32_t>(); }, n*k, 1);

		//this loop can be replaced with Peikert's and Yao's inversion methods - more efficient
		for (size_t i = 0; i < n * k; i++) {
			p2ZVector(i, 0) = dgg.GenerateInteger(0, sqrt(s * s - sigma * sigma), n);
		}

		//create k ring elements in coefficient representation
		Matrix<ILVector2n> p2 = SplitInt32AltIntoILVector2nElements(p2ZVector, n, va.GetParams());

		//now converting to evaluation representation before multiplication
		p2.SwitchFormat();

		Matrix<ILVector2n> TprimeMatrix = Tprime0.VStack(Tprime1);

		//the dimension is 2x1 - a vector of 2 ring elements
		Matrix<ILVector2n> Tp2 = TprimeMatrix * p2;

		//change to coefficient representation before converting to field elements
		Tp2(0, 0).SwitchFormat();
		Tp2(1, 0).SwitchFormat();

		Matrix<Field2n> c([]() { return make_unique<Field2n>(); }, 2, 1);

		c(0, 0) = Field2n(Tp2(0, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));
		c(1, 0) = Field2n(Tp2(1, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));

		Matrix<int32_t> p1ZVector([]() { return make_unique<int32_t>(); }, n * 2, 1);

		LatticeGaussSampUtility::ZSampleSigma2x2(a, b, d, c, &p1ZVector, dgg);

		for (size_t i = 0; i < 2 * n; i++) {
			(*perturbationVector)(i, 0) = p1ZVector(i, 0);
		}

		for (size_t i = 0; i < k * n; i++) {
			(*perturbationVector)(i + 2 * n, 0) = p2ZVector(i, 0);
		}

	}



} //end namespace crypto
