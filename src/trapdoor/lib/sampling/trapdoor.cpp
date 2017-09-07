/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: 
*		Dr. Yuriy Elementakov, <Elementakov@njit.edu>
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

#ifndef _SRC_LIB_CRYPTO_SIGNATURE_TRAPDOOR_CPP
#define _SRC_LIB_CRYPTO_SIGNATURE_TRAPDOOR_CPP

#include "cryptocontext.h"
#include "trapdoor.h"

namespace lbcrypto {

	//Trapdoor generation method as described in section 3.2 of https://eprint.iacr.org/2013/297.pdf (Construction 1)
	template <class Element>
	std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> RLWETrapdoorUtility<Element>::TrapdoorGen(shared_ptr<typename Element::Params> params, int stddev, int32_t base, bool bal)
	{
		auto zero_alloc = Element::MakeAllocator(params, EVALUATION);
		auto gaussian_alloc = Element::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, stddev);
		auto uniform_alloc = Element::MakeDiscreteUniformAllocator(params, EVALUATION);
//		size_t n = params->GetCyclotomicOrder() / 2;

		double val = params->GetModulus().ConvertToDouble();
		double nBits = floor(log2(val-1.0)+1.0);

		size_t k = std::ceil(nBits/log2(base));  /* (+1) is for balanced representation */

		if(bal == true){
			k++; // for a balanced digit representation, there is an extra digit required
		}

		auto a = uniform_alloc();

		Matrix<Element> r(zero_alloc, 1, k, gaussian_alloc);
		Matrix<Element> e(zero_alloc, 1, k, gaussian_alloc);

		//Converts discrete gaussians to Evaluation representation
		r.SwitchFormat();
		e.SwitchFormat();

		Matrix<Element> g = Matrix<Element>(zero_alloc, 1, k).GadgetVector(base);

		Matrix<Element> A(zero_alloc, 1, k+2);
		A(0,0) = 1;
		A(0,1) = *a;

		for (size_t i = 0; i < k; ++i) {
			A(0, i+2) = g(0, i) - (*a*r(0, i) + e(0, i));
		}

		return std::pair<Matrix<Element>, RLWETrapdoorPair<Element>>(A, RLWETrapdoorPair<Element>(r, e));

	}


	// Gaussian sampling based on the UCSD integer perturbation sampling

	template <class Element>
	Matrix<Element> RLWETrapdoorUtility<Element>::GaussSamp(size_t n, size_t k, const Matrix<Element>& A, 
		const RLWETrapdoorPair<Element>& T, const Element &u,
		typename Element::DggType &dgg, typename Element::DggType &dggLargeSigma, int32_t base){

		const shared_ptr<typename Element::Params> params = u.GetParams();
		auto zero_alloc = Element::MakeAllocator(params, EVALUATION);

		double c = (base + 1) * SIGMA;

		const typename Element::Integer& modulus = A(0, 0).GetModulus();

		//spectral bound s
		double s = SPECTRAL_BOUND(n,k,base);

		//perturbation vector in evaluation representation
		shared_ptr<Matrix<Element>> pHat(new Matrix<Element>(zero_alloc, k + 2, 1));

		ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, pHat);

		//pHat.SwitchFormat();

		//std::cout << pHat(0, 0) << std::endl;
		//std::cout << pHat(1, 0) << std::endl;
		//std::cout << pHat(2, 0) << std::endl;
		//std::cout << pHat(3, 0) << std::endl;

		//pHat.SwitchFormat();

		// YSP It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension of (k + 2) x 1
		// perturbedSyndrome is in the evaluation representation
		Element perturbedSyndrome = u - (A.Mult(*pHat))(0, 0);

		Matrix<int32_t> zHatBBI([]() { return make_unique<int32_t>(); }, k, n);

		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();

		LatticeGaussSampUtility<Element>::GaussSampGqArbBase(perturbedSyndrome, c, k, modulus, base, dgg, &zHatBBI);

		// Convert zHat from a matrix of BBI to a vector of Element ring elements
		// zHat is in the coefficient representation
		Matrix<Element> zHat = SplitInt32AltIntoElements<Element>(zHatBBI, n, params);
		// Now converting it to the evaluation representation before multiplication
		zHat.SwitchFormat();

		Matrix<Element> zHatPrime(zero_alloc, k + 2, 1);

		zHatPrime(0, 0) = (*pHat)(0, 0) + T.m_e.Mult(zHat)(0, 0);
		zHatPrime(1, 0) = (*pHat)(1, 0) + T.m_r.Mult(zHat)(0, 0);

		for (size_t row = 2; row < k + 2; ++row)
			zHatPrime(row, 0) = (*pHat)(row, 0) + zHat(row - 2, 0);

		//This code is helpful in tightening parameter constraints

		//zHatPrime(0, 0).SwitchFormat();
		//Element z0 = zHatPrime(0, 0);
		//zHatPrime(0, 0).SwitchFormat();

		//zHatPrime(1, 0).SwitchFormat();
		//Element z1 = zHatPrime(1, 0);
		//zHatPrime(1, 0).SwitchFormat();

		//std::cout << "z0=" << z0.Norm() << std::endl;
		//std::cout << "z1=" << z1.Norm() << std::endl;

		//zHatPrime(2, 0).SwitchFormat();
		//Element z2 = zHatPrime(2, 0);
		//zHatPrime(2, 0).SwitchFormat();

		//std::cout << "z2=" << z2.Norm() << std::endl;

		//pHat(0, 0).SwitchFormat();
		//Element pHat0 = pHat(0, 0);
		//pHat(0, 0).SwitchFormat();

		//std::cout << "pHat0=" << pHat0.Norm() << std::endl;

		//pHat(1, 0).SwitchFormat();
		//Element pHat1 = pHat(1, 0);
		//pHat(1, 0).SwitchFormat();

		//std::cout << "pHat1=" << pHat1.Norm() << std::endl;

		//pHat(2, 0).SwitchFormat();
		//Element pHat2 = pHat(2, 0);
		//pHat(2, 0).SwitchFormat();

		//std::cout << "pHat2=" << pHat2.Norm() << std::endl;

		//zHat(0, 0).SwitchFormat();
		//Element zHat2 = zHat(0, 0);
		//zHat(0, 0).SwitchFormat();

		//std::cout << "zHat=" << zHat2.Norm() << std::endl;

		return zHatPrime;

	}

	template <class Element>
	Matrix<Element> RLWETrapdoorUtility<Element>::GaussSampOnline(size_t n, size_t k, const Matrix<Element>& A,
		const RLWETrapdoorPair<Element>& T, const Element &u,
		typename Element::DggType &dgg, const shared_ptr<Matrix<Element>> pHat, int32_t base) {

		const shared_ptr<typename Element::Params> params = u.GetParams();
		auto zero_alloc = Element::MakeAllocator(params, EVALUATION);

		double c = (base + 1) * SIGMA;

		const typename Element::Integer& modulus = A(0, 0).GetModulus();

		// YSP It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension of (k + 2) x 1
		// perturbedSyndrome is in the evaluation representation
		Element perturbedSyndrome = u - (A.Mult(*pHat))(0, 0);

		Matrix<int32_t> zHatBBI([]() { return make_unique<int32_t>(); }, k, n);

		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();

		LatticeGaussSampUtility<Element>::GaussSampGqArbBase(perturbedSyndrome, c, k, modulus, base, dgg, &zHatBBI);

		// Convert zHat from a matrix of BBI to a vector of Element ring elements
		// zHat is in the coefficient representation
		Matrix<Element> zHat = SplitInt32AltIntoElements<Element>(zHatBBI, n, params);
		// Now converting it to the evaluation representation before multiplication
		zHat.SwitchFormat();

		Matrix<Element> zHatPrime(zero_alloc, k + 2, 1);

		zHatPrime(0, 0) = (*pHat)(0, 0) + T.m_e.Mult(zHat)(0, 0);
		zHatPrime(1, 0) = (*pHat)(1, 0) + T.m_r.Mult(zHat)(0, 0);

		for (size_t row = 2; row < k + 2; ++row)
			zHatPrime(row, 0) = (*pHat)(row, 0) + zHat(row - 2, 0);

		return zHatPrime;

	}

	template <class Element>
	shared_ptr<Matrix<Element>> RLWETrapdoorUtility<Element>::GaussSampOffline(size_t n, size_t k,
		const RLWETrapdoorPair<Element>& T, typename Element::DggType &dgg, typename Element::DggType &dggLargeSigma,
		int32_t base) {

		const shared_ptr<typename Element::Params> params = T.m_e(0, 0).GetParams();
		auto zero_alloc = Element::MakeAllocator(params, EVALUATION);

		double c = (base + 1) * SIGMA;

		//spectral bound s
		double s = SPECTRAL_BOUND(n, k, base);

		//perturbation vector in evaluation representation
		shared_ptr<Matrix<Element>> result(new Matrix<Element>(zero_alloc, k + 2, 1));

		ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, result);

		return result;

	}

	template <class Element>
	void RLWETrapdoorUtility<Element>::ZSampleSigmaP(size_t n, double s, double sigma,
		const RLWETrapdoorPair<Element>& Tprime,
		const typename Element::DggType &dgg, const typename Element::DggType &dggLargeSigma,
		shared_ptr<Matrix<Element>> perturbationVector) {

		Matrix<Element> Tprime0 = Tprime.m_e;
		Matrix<Element> Tprime1 = Tprime.m_r;

		// k is the bit length
		size_t k = Tprime0.GetCols();

		const shared_ptr<typename Element::Params> params = Tprime0(0, 0).GetParams();

		// all three Polynomials are initialized with "0" coefficients
		Element va(params, EVALUATION, 1);
		Element vb(params, EVALUATION, 1);
		Element vd(params, EVALUATION, 1);

		for (size_t i = 0; i < k; i++) {
			va = va + Tprime0(0, i)*Tprime0(0, i).Transpose();
			vb = vb + Tprime1(0, i)*Tprime0(0, i).Transpose();
			vd = vd + Tprime1(0, i)*Tprime1(0, i).Transpose();
		}

		//Switch the ring elements (Polynomials) to coefficient representation
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

		Matrix<int64_t> p2ZVector([]() { return make_unique<int64_t>(); }, n*k, 1);

		double sigmaLarge = sqrt(s * s - sigma * sigma);

		if (sigmaLarge > 3e5) {

			//std::cout << "sigmaLarge = " << sigmaLarge << std::endl;
			//std::cin.get();

			//Karney rejection method
			for (size_t i = 0; i < n * k; i++) {
				p2ZVector(i, 0) = dgg.GenerateIntegerKarney(0, sigmaLarge);
			}
		}
		else
		{

			//Peikert's inversion method
			std::shared_ptr<sint> dggVector = dggLargeSigma.GenerateIntVector(n*k);
	
			for (size_t i = 0; i < n * k; i++) {
				p2ZVector(i, 0) = (dggVector.get())[i];
			}

		}

		//create k ring elements in coefficient representation
		Matrix<Element> p2 = SplitInt64IntoElements<Element>(p2ZVector, n, va.GetParams());

		//now converting to evaluation representation before multiplication
		p2.SwitchFormat();

		Matrix<Element> TprimeMatrix = Tprime0.VStack(Tprime1);

		//the dimension is 2x1 - a vector of 2 ring elements
		Matrix<Element> Tp2 = TprimeMatrix * p2;

		//change to coefficient representation before converting to field elements
		Tp2.SwitchFormat();

		Matrix<Field2n> c([]() { return make_unique<Field2n>(); }, 2, 1);

		c(0, 0) = Field2n(Tp2(0, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));
		c(1, 0) = Field2n(Tp2(1, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));

		shared_ptr<Matrix<int64_t>> p1ZVector(new Matrix<int64_t>([]() { return make_unique<int64_t>(); }, n * 2, 1));

		LatticeGaussSampUtility<Element>::ZSampleSigma2x2(a, b, d, c, dgg, p1ZVector);

		//create 2 ring elements in coefficient representation
		Matrix<Element> p1 = SplitInt64IntoElements<Element>(*p1ZVector, n, va.GetParams());

		//Converts p1 to Evaluation representation
		p1.SwitchFormat();

		*perturbationVector = p1.VStack(p2);

	}


} //end namespace crypto

#endif
