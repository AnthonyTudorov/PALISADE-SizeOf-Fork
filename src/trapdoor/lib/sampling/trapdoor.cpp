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

#include "cryptocontext.h"
#include "trapdoor.h"

namespace lbcrypto {

	//Trapdoor generation method as described in section 3.2 of https://eprint.iacr.org/2013/297.pdf (Construction 1)
	std::pair<RingMat, RLWETrapdoorPair<ILVector2n>> RLWETrapdoorUtility::TrapdoorGen(shared_ptr<ILParams> params, int stddev)
	{
		auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
		auto gaussian_alloc = ILVector2n::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, stddev);
		auto uniform_alloc = ILVector2n::MakeDiscreteUniformAllocator(params, EVALUATION);

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

		//Converts discrete gaussians to Evaluation representation
		r.SwitchFormat();
		e.SwitchFormat();

		RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();

		RingMat A(zero_alloc, 1, k+2);
		A(0,0) = 1;
		A(0,1) = *a;

		for (size_t i = 0; i < k; ++i) {
			A(0, i+2) = g(0, i) - (*a*r(0, i) + e(0, i));
		}

		return std::pair<RingMat, RLWETrapdoorPair<ILVector2n>>(A, RLWETrapdoorPair<ILVector2n>(r, e));

	}

	// Gaussian sampling based on the UCSD integer perturbation sampling

	RingMat RLWETrapdoorUtility::GaussSamp(size_t n, size_t k, const RingMat& A, 
		const RLWETrapdoorPair<ILVector2n>& T, const ILVector2n &u,
		double sigma, ILVector2n::DggType &dgg, ILVector2n::DggType &dggLargeSigma) {

		const shared_ptr<ILParams> params = u.GetParams();
		auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

		//We should convert this to a static variable later
		//double c(2 * sqrt(log(2 * n*(1 + 1 / DG_ERROR)) / M_PI));

		double c = 2 * SIGMA;

		const BigBinaryInteger& modulus = A(0, 0).GetModulus();

		//spectral bound s
		double s = SPECTRAL_BOUND(n,k);
		//double s = 42 * std::sqrt(n*k);

		//perturbation vector in evaluation representation
		RingMat pHat(zero_alloc, k + 2, 1);

		ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, &pHat);

		//pHat.SwitchFormat();

		//std::cout << pHat(0, 0) << std::endl;
		//std::cout << pHat(1, 0) << std::endl;
		//std::cout << pHat(2, 0) << std::endl;
		//std::cout << pHat(3, 0) << std::endl;

		//pHat.SwitchFormat();

		// YSP It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension of (k + 2) x 1
		// perturbedSyndrome is in the evaluation representation
		ILVector2n perturbedSyndrome = u - (A.Mult(pHat))(0, 0);

		//Matrix<BigBinaryInteger> zHatBBI(BigBinaryInteger::Allocator, k, n);
		Matrix<int32_t> zHatBBI([]() { return make_unique<int32_t>(); }, k, n);

		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();

		LatticeGaussSampUtility::GaussSampGq(perturbedSyndrome, sigma, k, modulus, 2, dgg, &zHatBBI);

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

		//This code is helpful in tightening parameter constraints

		//zHatPrime(0, 0).SwitchFormat();
		//ILVector2n z0 = zHatPrime(0, 0);
		//zHatPrime(0, 0).SwitchFormat();

		//zHatPrime(1, 0).SwitchFormat();
		//ILVector2n z1 = zHatPrime(1, 0);
		//zHatPrime(1, 0).SwitchFormat();

		//std::cout << "z0=" << z0.Norm() << std::endl;
		//std::cout << "z1=" << z1.Norm() << std::endl;

		//zHatPrime(2, 0).SwitchFormat();
		//ILVector2n z2 = zHatPrime(2, 0);
		//zHatPrime(2, 0).SwitchFormat();

		//std::cout << "z2=" << z2.Norm() << std::endl;

		//pHat(0, 0).SwitchFormat();
		//ILVector2n pHat0 = pHat(0, 0);
		//pHat(0, 0).SwitchFormat();

		//std::cout << "pHat0=" << pHat0.Norm() << std::endl;

		//pHat(1, 0).SwitchFormat();
		//ILVector2n pHat1 = pHat(1, 0);
		//pHat(1, 0).SwitchFormat();

		//std::cout << "pHat1=" << pHat1.Norm() << std::endl;

		//pHat(2, 0).SwitchFormat();
		//ILVector2n pHat2 = pHat(2, 0);
		//pHat(2, 0).SwitchFormat();

		//std::cout << "pHat2=" << pHat2.Norm() << std::endl;

		//zHat(0, 0).SwitchFormat();
		//ILVector2n zHat2 = zHat(0, 0);
		//zHat(0, 0).SwitchFormat();

		//std::cout << "zHat=" << zHat2.Norm() << std::endl;

		return zHatPrime;

	}

	void RLWETrapdoorUtility::ZSampleSigmaP(size_t n, double s, double sigma,
		const RLWETrapdoorPair<ILVector2n>& Tprime,
		const ILVector2n::DggType &dgg, const ILVector2n::DggType &dggLargeSigma,
		RingMat *perturbationVector) {

		Matrix<ILVector2n> Tprime0 = Tprime.m_e;
		Matrix<ILVector2n> Tprime1 = Tprime.m_r;

		// k is the bit length
		size_t k = Tprime0.GetCols();

		const shared_ptr<ILParams> params = Tprime0(0, 0).GetParams();

		// all three polynomials are initialized with "0" coefficients
		ILVector2n va(params, EVALUATION, 1);
		ILVector2n vb(params, EVALUATION, 1);
		ILVector2n vd(params, EVALUATION, 1);

		for (size_t i = 0; i < k; i++) {
			va = va + Tprime0(0, i)*Tprime0(0, i).Transpose();
			vb = vb + Tprime1(0, i)*Tprime0(0, i).Transpose();
			vd = vd + Tprime1(0, i)*Tprime1(0, i).Transpose();
		}

		//Switch the ring elements (polynomials) to coefficient representation
		va.SwitchFormat();
		vb.SwitchFormat();
		vd.SwitchFormat();

		//std::cout << "a = " << std::endl;
		//va.PrintValues();
		//std::cout << "b = " << std::endl;
		//vb.PrintValues();
		//std::cout << "d = " << std::endl;
		//vd.PrintValues();

		//Create field elements from ring elements
		Field2n a(va), b(vb), d(vd);

		double scalarFactor = -s * s * sigma * sigma / (s * s - sigma * sigma);

		a = a.ScalarMult(scalarFactor);
		b = b.ScalarMult(scalarFactor);
		d = d.ScalarMult(scalarFactor);

		a = a + s*s;
		d = d + s*s;

		//converts the field elements to DFT representation
		a.SwitchFormat();
		b.SwitchFormat();
		d.SwitchFormat();

		Matrix<int32_t> p2ZVector([]() { return make_unique<int32_t>(); }, n*k, 1);

		//rejection method was used in the past
		//for (size_t i = 0; i < n * k; i++) {
		//	p2ZVector(i, 0) = dgg.GenerateInteger(0, sqrt(s * s - sigma * sigma), n);
		//}

		//Peikert's inversion method is used
		//YSP replace with smart pointers later
		std::shared_ptr<sint> dggVector = dggLargeSigma.GenerateIntVector(n*k);

		for (size_t i = 0; i < n * k; i++) {
			p2ZVector(i, 0) = (dggVector.get())[i];
		}

		//create k ring elements in coefficient representation
		Matrix<ILVector2n> p2 = SplitInt32IntoILVector2nElements(p2ZVector, n, va.GetParams());

		//now converting to evaluation representation before multiplication
		p2.SwitchFormat();

		Matrix<ILVector2n> TprimeMatrix = Tprime0.VStack(Tprime1);

		//the dimension is 2x1 - a vector of 2 ring elements
		Matrix<ILVector2n> Tp2 = TprimeMatrix * p2;

		//change to coefficient representation before converting to field elements
		Tp2.SwitchFormat();

		Matrix<Field2n> c([]() { return make_unique<Field2n>(); }, 2, 1);

		c(0, 0) = Field2n(Tp2(0, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));
		c(1, 0) = Field2n(Tp2(1, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));

		Matrix<int32_t> p1ZVector([]() { return make_unique<int32_t>(); }, n * 2, 1);

		LatticeGaussSampUtility::ZSampleSigma2x2(a, b, d, c, dgg, &p1ZVector);

		//create 2 ring elements in coefficient representation
		Matrix<ILVector2n> p1 = SplitInt32IntoILVector2nElements(p1ZVector, n, va.GetParams());

		//Converts p1 to Evaluation representation
		p1.SwitchFormat();

		*perturbationVector = p1.VStack(p2);

	}


} //end namespace crypto
