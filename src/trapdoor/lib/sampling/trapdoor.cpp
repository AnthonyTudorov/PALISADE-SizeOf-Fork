/**
 * @file trapdoor.cpp Provides the utility for sampling trapdoor lattices as described in https://eprint.iacr.org/2017/844.pdf
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#ifndef _SRC_LIB_CRYPTO_SIGNATURE_TRAPDOOR_CPP
#define _SRC_LIB_CRYPTO_SIGNATURE_TRAPDOOR_CPP

#include "cryptocontext.h"
#include "trapdoor.h"

namespace lbcrypto {

	template <class Element>
	std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> RLWETrapdoorUtility<Element>::TrapdoorGenSquareMat(shared_ptr<typename Element::Params> params,
			int stddev, size_t d, int64_t base, bool bal)
	{
		auto zero_alloc = Element::Allocator(params, EVALUATION);
		auto gaussian_alloc = Element::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, stddev);
		auto uniform_alloc = Element::MakeDiscreteUniformAllocator(params, EVALUATION);

		double val = params->GetModulus().ConvertToDouble();
		double nBits = ceil(log2(val));

		size_t k = std::ceil(nBits/log2(base));  /* (+1) is for balanced representation */

		if(bal == true){
			k++; // for a balanced digit representation, there is an extra digit required
		}

		Matrix<Element> R(zero_alloc, d, d*k, gaussian_alloc);
		Matrix<Element> E(zero_alloc, d, d*k, gaussian_alloc);

		Matrix<Element> Abar(zero_alloc, d, d, uniform_alloc);

		//Converts discrete gaussians to Evaluation representation
		R.SwitchFormat();
		E.SwitchFormat();

		Matrix<Element> G = Matrix<Element>(zero_alloc, d, d*k).GadgetVector(base);

		Matrix<Element> A(zero_alloc, d, d*2);

		for(size_t i = 0; i < d; i++)
		{
			for(size_t j = 0; j < d; j++)
			{
				A(i,j) = Abar(i,j);
				if (i==j)
					A(i,j+d) = 1;
				else
					A(i,j+d) = 0;
			}
		}

		Matrix<Element> A1 = G - (Abar*R + E);

		A.HStack(A1);

		return std::pair<Matrix<Element>, RLWETrapdoorPair<Element>>(A, RLWETrapdoorPair<Element>(R, E));

	}

	// Gaussian sampling as described in Alogorithm 2 of https://eprint.iacr.org/2017/844.pdf

	template <class Element>
	Matrix<Element> RLWETrapdoorUtility<Element>::GaussSamp(size_t n, size_t k, const Matrix<Element>& A,
		const RLWETrapdoorPair<Element>& T, const Element &u,
		typename Element::DggType &dgg, typename Element::DggType &dggLargeSigma, int64_t base){
                bool dbg_flag = false;
		TimeVar t1, t1_tot, t2, t2_tot, t3, t3_tot;
		TIC(t1);
		TIC(t1_tot);
		const shared_ptr<typename Element::Params> params = u.GetParams();
		auto zero_alloc = Element::Allocator(params, EVALUATION);

		double c = (base + 1) * SIGMA;

		const typename Element::Integer& modulus = A(0, 0).GetModulus();

		//spectral bound s
		double s = SPECTRAL_BOUND(n,k,base);

		DEBUG("c " << c << " s " << s);

		//perturbation vector in evaluation representation
		shared_ptr<Matrix<Element>> pHat(new Matrix<Element>(zero_alloc, k + 2, 1));
		DEBUG("t1a: "<<TOC(t1));
		TIC(t1);
		ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, pHat);
		DEBUG("t1b: "<<TOC(t1)); //this takes the most time 61
		TIC(t1);
		// It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension of (k + 2) x 1
		// perturbedSyndrome is in the evaluation representation
		Element perturbedSyndrome = u - (A.Mult(*pHat))(0, 0);

//		DEBUG("t1c: "<<TOC(t1)); //takes 2
		TIC(t1);
		Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);
		DEBUG("t1d: "<<TOC(t1)); //takes 0
		DEBUG("t1: "<<TOC(t1_tot));//takes 64
		TIC(t2);
		TIC(t2_tot);
		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();
		DEBUG("t2a: "<<TOC(t2)); //takes 1
		TIC(t2);
		LatticeGaussSampUtility<Element>::GaussSampGqArbBase(perturbedSyndrome, c, k, modulus, base, dgg, &zHatBBI);
		DEBUG("t2b: "<<TOC(t2)); //takes 36
		TIC(t2);
		// Convert zHat from a matrix of BBI to a vector of Element ring elements
		// zHat is in the coefficient representation
		Matrix<Element> zHat = SplitInt64AltIntoElements<Element>(zHatBBI, n, params);

		DEBUG("t2c: "<<TOC(t2)); //takes 0
		// Now converting it to the evaluation representation before multiplication
		zHat.SwitchFormat();
		DEBUG("t2d: "<<TOC(t2)); //takes 17
		DEBUG("t2: "<<TOC(t2_tot));
		//TIC(t3); seems trivial
		Matrix<Element> zHatPrime(zero_alloc, k + 2, 1);

		zHatPrime(0, 0) = (*pHat)(0, 0) + T.m_e.Mult(zHat)(0, 0);
		zHatPrime(1, 0) = (*pHat)(1, 0) + T.m_r.Mult(zHat)(0, 0);

		for (size_t row = 2; row < k + 2; ++row)
			zHatPrime(row, 0) = (*pHat)(row, 0) + zHat(row - 2, 0);
		//DEBUG("t3: "<<TOC(t3));
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

	// Gaussian sampling as described in "Implementing Token-Based Obfuscation..."

	template <class Element>
	Matrix<Element> RLWETrapdoorUtility<Element>::GaussSampSquareMat(size_t n, size_t k, const Matrix<Element>& A,
		const RLWETrapdoorPair<Element>& T, const Matrix<Element>& U,
		typename Element::DggType &dgg, typename Element::DggType &dggLargeSigma, int64_t base)
	{

		const shared_ptr<typename Element::Params> params = U(0,0).GetParams();
		auto zero_alloc = Element::Allocator(params, EVALUATION);

		double c = (base + 1) * SIGMA;

		const typename Element::Integer& modulus = A(0, 0).GetModulus();

		size_t d = T.m_r.GetRows();

		//spectral bound s
		double s = SPECTRAL_BOUND_D(n,k,base,d);

		//perturbation vector in evaluation representation
		shared_ptr<Matrix<Element>> pHat(new Matrix<Element>(zero_alloc, d*(k + 2), d));

		SamplePertSquareMat(n, s, c, T, dgg, dggLargeSigma, pHat);

		// It is assumed that A has dimension d x d*(k + 2) and pHat has the dimension of d*(k + 2) x d
		// perturbedSyndrome is in the evaluation representation
		Matrix<Element> perturbedSyndrome = U - (A.Mult(*pHat));

		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();

		Matrix<Element> zHatMat(zero_alloc, d*k, d);

		for (size_t i = 0; i < d; i++)
		{
			for (size_t j = 0; j < d; j++)
			{
				Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);

				LatticeGaussSampUtility<Element>::GaussSampGqArbBase(perturbedSyndrome(i,j), c, k, modulus, base, dgg, &zHatBBI);

				// Convert zHat from a matrix of BBI to a vector of Element ring elements
				// zHat is in the coefficient representation
				Matrix<Element> zHat = SplitInt64AltIntoElements<Element>(zHatBBI, n, params);

				// Now converting it to the evaluation representation before multiplication
				zHat.SwitchFormat();

				for(size_t p=0; p<k; p++)
					zHatMat(i*k + p,j) = zHat(p,0);
			}
		}

		Matrix<Element> zHatPrime(zero_alloc, d*(k + 2), d);

		Matrix<Element> rZhat = T.m_r.Mult(zHatMat); // d x d
		Matrix<Element> eZhat = T.m_e.Mult(zHatMat); // d x d

		for (size_t j = 0; j < d; j++) { // columns
			for (size_t i = 0; i < d; i++) {
				zHatPrime(i,j) =  (*pHat)(i,j) +  rZhat(i,j);
				zHatPrime(i+d,j) =  (*pHat)(i+d,j) + eZhat(i,j);

				for (size_t p = 0; p < k; p++) {
					zHatPrime(i*k + p + 2*d,j) =  (*pHat)(i*k + p + 2*d,j) + zHatMat(i*k + p,j);
				}
			}
		}

		//pHat->SwitchFormat();

		//std::cerr << "s = " << s << std::endl;

		//std::cerr << "pHat = " << *pHat << std::endl;

		return zHatPrime;

	}

	// On-line stage of pre-image sampling (includes only G-sampling)

	template <class Element>
	Matrix<Element> RLWETrapdoorUtility<Element>::GaussSampOnline(size_t n, size_t k, const Matrix<Element>& A,
		const RLWETrapdoorPair<Element>& T, const Element &u,
		typename Element::DggType &dgg, const shared_ptr<Matrix<Element>> pHat, int64_t base) {

		const shared_ptr<typename Element::Params> params = u.GetParams();
		auto zero_alloc = Element::Allocator(params, EVALUATION);

		double c = (base + 1) * SIGMA;

		const typename Element::Integer& modulus = A(0, 0).GetModulus();

		// It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension of (k + 2) x 1
		// perturbedSyndrome is in the evaluation representation
		Element perturbedSyndrome = u - (A.Mult(*pHat))(0, 0);

		Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);

		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();

		LatticeGaussSampUtility<Element>::GaussSampGqArbBase(perturbedSyndrome, c, k, modulus, base, dgg, &zHatBBI);

		// Convert zHat from a matrix of integers to a vector of Element ring elements
		// zHat is in the coefficient representation
		Matrix<Element> zHat = SplitInt64AltIntoElements<Element>(zHatBBI, n, params);
		// Now converting it to the evaluation representation before multiplication
		zHat.SwitchFormat();

		Matrix<Element> zHatPrime(zero_alloc, k + 2, 1);

		zHatPrime(0, 0) = (*pHat)(0, 0) + T.m_e.Mult(zHat)(0, 0);
		zHatPrime(1, 0) = (*pHat)(1, 0) + T.m_r.Mult(zHat)(0, 0);

		for (size_t row = 2; row < k + 2; ++row)
			zHatPrime(row, 0) = (*pHat)(row, 0) + zHat(row - 2, 0);

		return zHatPrime;

	}

	// Offline stage of pre-image sampling (perturbation sampling)

	template <class Element>
	shared_ptr<Matrix<Element>> RLWETrapdoorUtility<Element>::GaussSampOffline(size_t n, size_t k,
		const RLWETrapdoorPair<Element>& T, typename Element::DggType &dgg, typename Element::DggType &dggLargeSigma,
		int64_t base) {

		const shared_ptr<typename Element::Params> params = T.m_e(0, 0).GetParams();
		auto zero_alloc = Element::Allocator(params, EVALUATION);

		double c = (base + 1) * SIGMA;

		//spectral bound s
		double s = SPECTRAL_BOUND(n, k, base);

		//perturbation vector in evaluation representation
		shared_ptr<Matrix<Element>> result(new Matrix<Element>(zero_alloc, k + 2, 1));
		ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, result);

		return result;
	}
	template<>
	inline void RLWETrapdoorUtility<DCRTPoly>::ZSampleSigmaP(size_t n, double s, double sigma,
			const RLWETrapdoorPair<DCRTPoly> &Tprime,
			const DCRTPoly::DggType& dgg, const DCRTPoly::DggType& dggLargeSigma,
			shared_ptr<Matrix<DCRTPoly>> perturbationVector){
		bool dbg_flag = false;
		TimeVar t1, t2, t3, t1_tot, t2_tot, t3_tot;

		TIC(t1);
		TIC(t1_tot);
		Matrix<DCRTPoly> Tprime0 = Tprime.m_e;
		Matrix<DCRTPoly> Tprime1 = Tprime.m_r;
		// k is the bit length
		size_t k = Tprime0.GetCols();

			const shared_ptr<DCRTPoly::Params> params = Tprime0(0, 0).GetParams();
			//NativePoly::Params nParams(params->GetCyclotomicOrder(), params->GetModulus(), params->GetRootOfUnity(), params->GetBigModulus(), params->GetBigRootOfUnity());


			DEBUG("z1a: "<<TOC(t1)); //0
			TIC(t1);
			// all three Polynomials are initialized with "0" coefficients
			NativePoly va((*params)[0], EVALUATION, 1);
			NativePoly vb((*params)[0], EVALUATION, 1);
			NativePoly vd((*params)[0], EVALUATION, 1);

			for (size_t i = 0; i < k; i++) {
				va += (NativePoly)Tprime0(0, i).GetElementAtIndex(0)*Tprime0(0, i).Transpose().GetElementAtIndex(0);
				vb += (NativePoly)Tprime1(0, i).GetElementAtIndex(0)*Tprime0(0, i).Transpose().GetElementAtIndex(0);
				vd += (NativePoly)Tprime1(0, i).GetElementAtIndex(0)*Tprime1(0, i).Transpose().GetElementAtIndex(0);
			}
			DEBUG("z1b: "<<TOC(t1)); //9
			TIC(t1);

			//Switch the ring elements (Polynomials) to coefficient representation
			va.SwitchFormat();
			vb.SwitchFormat();
			vd.SwitchFormat();

			DEBUG("z1c: "<<TOC(t1));  //5
			TIC(t1);


			//Create field elements from ring elements
			Field2n a(va), b(vb), d(vd);

			double scalarFactor = -s * s * sigma * sigma / (s * s - sigma * sigma);

			a = a.ScalarMult(scalarFactor);
			b = b.ScalarMult(scalarFactor);
			d = d.ScalarMult(scalarFactor);

			a = a + s*s;
			d = d + s*s;
			DEBUG("z1d: "<<TOC(t1)); //0
			TIC(t1);

			//converts the field elements to DFT representation
			a.SwitchFormat();
			b.SwitchFormat();
			d.SwitchFormat();
			DEBUG("z1e: "<<TOC(t1)); //0
			TIC(t1);

			Matrix<int64_t> p2ZVector([]() { return 0; }, n*k, 1);

			double sigmaLarge = sqrt(s * s - sigma * sigma);

			// for distribution parameters up to 3e5 (experimentally found threshold) use the Peikert's inversion method
			// otherwise, use Karney's method
			if (sigmaLarge > 3e5) {

				//Karney rejection method
				for (size_t i = 0; i < n * k; i++) {
					p2ZVector(i, 0) = dgg.GenerateIntegerKarney(0, sigmaLarge);
				}
			}
			else
			{

				//Peikert's inversion method
				std::shared_ptr<int32_t> dggVector = dggLargeSigma.GenerateIntVector(n*k);

				for (size_t i = 0; i < n * k; i++) {
					p2ZVector(i, 0) = (dggVector.get())[i];
				}

			}
			DEBUG("z1f1: "<<TOC(t1));
			TIC(t1);

			//create k ring elements in coefficient representation
			Matrix<DCRTPoly> p2 = SplitInt64IntoElements<DCRTPoly>(p2ZVector, n, params);
			DEBUG("z1f2: "<<TOC(t1));
			TIC(t1);

			//now converting to evaluation representation before multiplication
			p2.SwitchFormat();

			DEBUG("z1g: "<<TOC(t1));  //17
			TIC(t1);

			//Matrix<DCRTPoly> TprimeMatrix = Tprime0.VStack(Tprime1);
			DEBUG("z1h1: "<<TOC(t1));
			TIC(t1);

			auto zero_alloc = NativePoly::Allocator((*params)[0], EVALUATION);
			Matrix<NativePoly> Tp2(zero_alloc, 2, 1);
			for(unsigned int i=0;i<k;i++){
				Tp2(0,0)+= Tprime0(0,i).GetElementAtIndex(0) * (NativePoly)p2(i,0).GetElementAtIndex(0);
				Tp2(1,0)+= Tprime1(0,i).GetElementAtIndex(0) * (NativePoly)p2(i,0).GetElementAtIndex(0);
			}

			DEBUG("z1h2: "<<TOC(t1));
			TIC(t1);
			//change to coefficient representation before converting to field elements
			Tp2.SwitchFormat();
			DEBUG("z1h3: "<<TOC(t1));
			TIC(t1);

			Matrix<Field2n> c([]() { return Field2n(); }, 2, 1);

			c(0, 0) = Field2n(Tp2(0, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));
			c(1, 0) = Field2n(Tp2(1, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));

			shared_ptr<Matrix<int64_t>> p1ZVector(new Matrix<int64_t>([]() { return 0; }, n * 2, 1));
			DEBUG("z1i: "<<TOC(t1));
			TIC(t1);

			LatticeGaussSampUtility<DCRTPoly>::ZSampleSigma2x2(a, b, d, c, dgg, p1ZVector);
			DEBUG("z1j1: "<<TOC(t1)); //14
			TIC(t1);

			//create 2 ring elements in coefficient representation
			Matrix<DCRTPoly> p1 = SplitInt64IntoElements<DCRTPoly>(*p1ZVector, n, params);
			DEBUG("z1j2: "<<TOC(t1));
			TIC(t1);

			//Converts p1 to Evaluation representation
			p1.SwitchFormat();
			DEBUG("z1j3: "<<TOC(t1));
			TIC(t1);

			*perturbationVector = p1.VStack(p2);
			DEBUG("z1j4: "<<TOC(t1));
			TIC(t1);
			DEBUG("z1tot: "<<TOC(t1_tot));
		}


} //end namespace crypto
#endif
