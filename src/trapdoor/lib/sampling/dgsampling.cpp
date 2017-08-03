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
* This code provides the utility for lattice Gaussian sampling (needed by lattice trapdoors).
*/

#ifndef _SRC_LIB_TRAPDOOR_DGSAMPLING_CPP
#define _SRC_LIB_TRAPDOOR_DGSAMPLING_CPP

#include "cryptocontext.h"
#include "dgsampling.h"

namespace lbcrypto {

	// Gaussian sampling from lattice for gagdet matrix G and syndrome u ONLY FOR A POWER-OF-TWO MODULUS; Has not been fully tested
	// DISABLED

	//template <class Element>
	//void LatticeGaussSampUtility<Element>::GaussSampG(const Element &u, double sttdev, size_t k,
	//		typename Element::DggType &dgg, Matrix<typename Element::Integer> *z)
	//{
	//	const typename Element::Integer& modulus = u.GetParams()->GetModulus();
	//	for (size_t i = 0; i < u.GetLength(); i++) {

	//		//initial value of integer syndrome corresponding to component u_i
	//		typename Element::Integer t(u.GetValAtIndex(i));

	//		for (size_t j = 0; j < k; j++) {

	//			//get the least significant digit of t; used for choosing the right coset to sample from 2Z or 2Z+1
	//			uint32_t lsb = t.GetDigitAtIndexForBase(1, 2);

	//			//dgLSB keeps track of the least significant bit of discrete gaussian; initialized to 2 to make sure the loop is entered
	//			uint32_t dgLSB = 2;
	//			typename Element::Integer sampleInteger;

	//			//checks if the least significant bit of t matches the least signficant bit of a discrete Gaussian sample
	//			while (dgLSB != lsb)
	//			{
	//				sampleInteger = dgg.GenerateInteger(modulus);
	//				dgLSB = sampleInteger.GetDigitAtIndexForBase(1, 2);
	//			}

	//			(*z)(j, i) = sampleInteger;

	//			//division by 2
	//			// TODO: Probably incorrect, but this whole function is wrong anyways. Awaiting advice of Daniele
	//			t = (t.ModSub((*z)(j, i), modulus)) >> 1;
	//			//t = (t - (*z)(j,i))>>1;

	//		}

	//	}

	//}

	// Gaussian sampling from lattice for gagdet matrix G and syndrome u and ARBITRARY MODULUS q - Improved algorithm
	// Algorithm was provided in a personal communication by Daniele Micciancio
	// It will be published in GM17

	template <class Element>
	void LatticeGaussSampUtility<Element>::GaussSampGq(const Element &u, double stddev, size_t k, const typename Element::Integer &q, int32_t base,
		typename Element::DggType &dgg, Matrix<int32_t> *z)
	{
		const typename Element::Integer& modulus = u.GetParams()->GetModulus();
		// std::cout << "modulus = " << modulus << std::endl; 
		double sigma = stddev / (base + 1);

		// main diagonal of matrix L
		std::vector<double> l(k);
		//upper diagonal of matrix L
		std::vector<double> h(k);

		//Matrix<double> a([]() { return make_unique<double>(); }, k, 1);
		Matrix<double> c([]() { return make_unique<double>(); }, k, 1);

		//  set the values of matrix L
		// (double) is added to avoid integer division
		l[0] = sqrt(base*(1 + 1 / k) + 1);
		for (size_t i = 1; i < k; i++)
			l[i] = sqrt(base*(1 + 1 / (double)(k - i)));

		h[0] = 0;
		// (double) is added to avoid integer division
		for (size_t i = 1; i < k; i++)
			h[i] = sqrt(base*(1 - 1 / (double)(k - (i - 1))));

		// c can be pre-computed as it only depends on the modulus
		// (double) is added to avoid integer division
		c(0, 0) = modulus.GetDigitAtIndexForBase(1, base) / (double)base;

		for (size_t i = 1; i < k; i++)
			c(i, 0) = (c(i - 1, 0) + modulus.GetDigitAtIndexForBase(i + 1, base)) / base;

#pragma omp parallel for
		for (size_t j = 0; j < u.GetLength(); j++)
		{
			typename Element::Integer v(u.GetValAtIndex(j));

			vector<int32_t> p(k);

			LatticeGaussSampUtility<Element>::Perturb(sigma, k, u.GetLength(), l, h, base, dgg, &p);

			Matrix<double> a([]() { return make_unique<double>(); }, k, 1);

			// int32_t cast is needed here as GetDigitAtIndexForBase returns an unsigned int
			// when the result is negative, a(0,0) gets values close to 2^32 if the cast is not used
			//****a(0, 0) = ((int32_t)(v.GetDigitAtIndexForBase(1, base)) - p[0]) / base;
			// (double) is added to avoid integer division
			a(0, 0) = ((int32_t)(v.GetDigitAtIndexForBase(1, base)) - p[0]) / (double)base;

			for (size_t t = 1; t < k; t++){
				a(t, 0) = (a(t - 1, 0) + (int32_t)(v.GetDigitAtIndexForBase(t + 1, base)) - p[t]) / base;
			}
			vector<int32_t> zj(k);

			LatticeGaussSampUtility<Element>::SampleC(c, k, u.GetLength(), sigma, dgg, &a, &zj);

			(*z)(0, j) = base*zj[0] + modulus.GetDigitAtIndexForBase(1, base)*zj[k - 1] + v.GetDigitAtIndexForBase(1, base);

			for (size_t t = 1; t < k - 1; t++){
					(*z)(t, j) = base*zj[t] - zj[t - 1] + modulus.GetDigitAtIndexForBase(t + 1, base)*zj[k - 1] + v.GetDigitAtIndexForBase(t + 1, base);
			}
			(*z)(k - 1, j) = modulus.GetDigitAtIndexForBase(k, base)*zj[k - 1] - zj[k - 2] + v.GetDigitAtIndexForBase(k, base);
		}

	}

	// subroutine used by GaussSampGqV2
	// Algorithm was provided in a personal communication by Daniele Micciancio
	// It will be published in GM17 (EuroCrypt)

	template <class Element>
	void LatticeGaussSampUtility<Element>::Perturb(double sigma, size_t k, size_t n,
		const vector<double> &l, const vector<double> &h, int32_t base, typename Element::DggType &dgg, vector<int32_t> *p) {

		std::vector<int32_t> z(k);
		double d = 0;

		for (size_t i = 0; i < k; i++)
		{
			z[i] = dgg.GenerateIntegerKarney(d / l[i], sigma / l[i]);
			//z[i] = dgg.GenerateInteger(d / l[i], sigma / l[i], n);
			d = -z[i] * h[i];
		}

		(*p)[0] = (2 * base + 1)*z[0] + base*z[1];
		for (size_t i = 1; i < k - 1; i++)
			(*p)[i] = base*(z[i - 1] + 2 * z[i] + z[i + 1]);
		(*p)[k - 1] = base*(z[k - 2] + 2 * z[k - 1]);

	}

	// subroutine used by GaussSampGq
	// Algorithm was provided in a personal communication by Daniele Micciancio
	// It will be published in GM17 (EuroCrypt)

	template <class Element>
	void LatticeGaussSampUtility<Element>::SampleC(const Matrix<double> &c, size_t k, size_t n,
		double sigma, typename Element::DggType &dgg, Matrix<double> *a, vector<int32_t> *z)
	{
		(*z)[k - 1] = dgg.GenerateIntegerKarney(-(*a)(k - 1, 0) / c(k - 1, 0), sigma / c(k - 1, 0));
		//(*z)[k - 1] = dgg.GenerateInteger(-(*a)(k - 1, 0) / c(k - 1, 0), sigma / c(k - 1, 0),n);
		*a = *a - ((double)((*z)[k - 1]))*c;

		for (size_t i = 0; i < k - 1; i++) { 
			(*z)[i] = dgg.GenerateIntegerKarney(-(*a)(i, 0), sigma);
			//(*z)[i] = dgg.GenerateInteger(-(*a)(i, 0), sigma, n);
		}

	}
	
	//Subroutine used by ZSampleSigmaP
	// a - field element in DFT format
	// b - field element in DFT format
	// d - field element in DFT format
	// c - vector of field elements in Coefficient format
	template <class Element>
	void LatticeGaussSampUtility<Element>::ZSampleSigma2x2(const Field2n &a, const Field2n &b,
		const Field2n &d, const Matrix<Field2n> &c, const typename Element::DggType & dgg, shared_ptr<Matrix<int32_t>> q) {

			//size of the the lattice
		    size_t n = a.Size();

			Field2n dCoeff = d;
			//Converts to coefficient representation
			dCoeff.SwitchFormat();

			shared_ptr<Matrix<int32_t>> q2Int  = ZSampleF(dCoeff,c(1,0),dgg,n);
			Field2n q2(*q2Int);
			
			Field2n q2Minusc2 = q2 - c(1, 0);
			//Convert to DFT representation prior to multiplication
			q2Minusc2.SwitchFormat();

			Field2n product = b * d.Inverse() * q2Minusc2;
			//Convert the product to coefficient representation
			product.SwitchFormat();
			
			//Computes c1 in coefficient format
			Field2n c1 = c(0, 0) + product;

			Field2n f = a - b*d.Inverse()*b.Transpose();
			//Convert to coefficient representation
			f.SwitchFormat();

			shared_ptr<Matrix<int32_t>> q1Int = ZSampleF(f, c1, dgg, n);

			for (size_t i = 0; i < q1Int->GetRows(); i++) {
				(*q)(i, 0) = (*q1Int)(i,0);
			}

			for (size_t i = 0; i < q2Int->GetRows(); i++) {
				(*q)(i + q1Int->GetRows(), 0) = (*q2Int)(i, 0);
			}

	}

	//Subroutine used by ZSampleSigma2x2
	//f is in Coefficient representation
	//c is in Coefficient representation
	template <class Element>
	shared_ptr<Matrix<int32_t>> LatticeGaussSampUtility<Element>::ZSampleF(const Field2n &f, const Field2n &c,
		const typename Element::DggType &dgg, size_t n) {

		if (f.Size() == 1)
		{
			shared_ptr<Matrix<int32_t>> p(new Matrix<int32_t>([]() { return make_unique<int32_t>(); }, 1, 1));
			(*p)(0, 0) = dgg.GenerateIntegerKarney(c[0].real(), sqrt(f[0].real()));
			//p(0, 0) = dgg.GenerateInteger(c[0].real(), sqrt(f[0].real()),n);
			return p;
		}
		else {

			Field2n f0 = f.ExtractEven();
			Field2n f1 = f.ExtractOdd();

			//converts to evaluation representation
			f0.SwitchFormat();
			f1.SwitchFormat();

			usint n = f0.Size();

			shared_ptr<Matrix<int32_t>> qZVector(new Matrix<int32_t>([]() { return make_unique<int32_t>(); },  n * 2, 1));

			Matrix<Field2n> cPermuted([]() { return make_unique<Field2n>(); }, 2, 1);

			cPermuted(0, 0) = c.ExtractEven();
			cPermuted(1, 0) = c.ExtractOdd();

			LatticeGaussSampUtility<Element>::ZSampleSigma2x2(f0, f1, f0, cPermuted, dgg, qZVector);

			InversePermute(qZVector);

			return qZVector;

		}

	}

	template <class Element>
	Matrix<int32_t> LatticeGaussSampUtility<Element>::Permute(Matrix<int32_t> * p) {
		int evenPtr = 0;
		int oddPtr = p->GetRows() / 2;
		Matrix<int32_t> permuted([]() { return make_unique<int32_t>(); }, p->GetRows(), 1);
		for (usint i = 0;i < p->GetRows();i++) {
			if (i % 2 == 0) {
				permuted(evenPtr,0) = (*p)(i,0);
				evenPtr++;
			}
			else {
				permuted(oddPtr, 0) = (*p)(i, 0);
				oddPtr++;
			}
		}
		return permuted;
	}

	template <class Element>
	void LatticeGaussSampUtility<Element>::InversePermute(shared_ptr<Matrix<int32_t>> p)
	{

		// a vector of int32_t is used for intermediate storage because it is faster
		// than a Matrix of unique pointers to int32_t

		std::vector<int32_t> vectorPermuted(p->GetRows());

		size_t evenPtr = 0;
		size_t oddPtr = vectorPermuted.size() / 2;
		for (size_t i = 0; evenPtr < vectorPermuted.size() / 2; i += 2) {
			vectorPermuted[i] = (*p)(evenPtr, 0);
			vectorPermuted[i + 1] = (*p)(oddPtr, 0);
			evenPtr++;
			oddPtr++;
		}

		for (size_t i = 0; i < vectorPermuted.size(); i++) {
			(*p)(i, 0) = vectorPermuted[i];
		}

	}

	// OLD CODE

	//Matrix<int32_t> LatticeGaussSampUtility::InversePermute(Matrix<int32_t> *p)
	//{

	//		Matrix<int32_t> invpermuted([]() { return make_unique<int32_t>(); }, p->GetRows(), 1);
	//		size_t evenPtr = 0;
	//		size_t oddPtr = p->GetRows() / 2;
	//		for (size_t i = 0; evenPtr < p->GetRows() / 2; i += 2) {
	//			invpermuted(i,0) = (*p)(evenPtr,0);
	//			invpermuted(i + 1,0) = (*p)(oddPtr,0);
	//			evenPtr++;
	//			oddPtr++;
	//		}
	//		return invpermuted;
	//}

	//Subroutine used by ZSampleSigma2x2
	//f is in Coefficient representation
	//c is in Coefficient representation
	//Matrix<int32_t> LatticeGaussSampUtility::ZSampleFOld(const Field2n &f, const Field2n &c,
	//	const Element::DggType &dgg, size_t n) {

	//	if (f.Size() == 1)
	//	{
	//		Matrix<int32_t> p([]() { return make_unique<int32_t>(); }, 1, 1);
	//		p(0, 0) = dgg.GenerateIntegerKarney(c[0].real(), sqrt(f[0].real()));
	//		//p(0, 0) = dgg.GenerateInteger(c[0].real(), sqrt(f[0].real()),n);
	//		return p;
	//	}
	//	else {

	//		// Here, we apply the inverse of the permutation matrix, which is the same as the transpose of the 
	//		// permutation matrix since the permutation matrix is orthogonal
	//		Field2n cNew(c.InversePermute());

	//		Field2n fe = f.ExtractEven();
	//		Field2n fo = f.ExtractOdd();

	//		// Stores fe in coefficient representation to be used later
	//		Field2n feCoeff = fe;

	//		Field2n c1(cNew.Size() / 2, COEFFICIENT);
	//		Field2n c2(cNew.Size() / 2, COEFFICIENT);

	//		// c1 corresponds to even coefficients
	//		for (size_t i = 0; i < c1.Size(); i++) {
	//			c1[i] = cNew[i];
	//		}

	//		// c2 corresponds to odd coefficients
	//		for (size_t i = 0; i < c2.Size(); i++) {
	//			c2[i] = cNew[i + c1.Size()];
	//		}

	//		Matrix<int32_t> r2Int = ZSampleF(fe, c2, dgg, n);
	//		Field2n r2(r2Int);

	//		Field2n r2Minusc2 = r2 - c2;
	//		//Convert to DFT represenation prior to multiplication
	//		r2Minusc2.SwitchFormat();

	//		//Convert fo and fe to DFT Format
	//		fe.SwitchFormat();
	//		fo.SwitchFormat();

	//		Field2n product = fo * fe.Inverse() * r2Minusc2;
	//		//Convert the product to coefficient representation
	//		product.SwitchFormat();

	//		//Compute c1 in coefficient representation
	//		c1 = c1 + product;

	//		Field2n product2 = fo * fo * fe.Inverse();
	//		//Convert the product to coefficient representation
	//		product2.SwitchFormat();

	//		Matrix<int32_t> r1Int = ZSampleF(feCoeff - product2.ShiftRight(), c1, dgg, n);

	//		Matrix<int32_t> rInt = r1Int.VStack(r2Int);
	//		return Permute(&rInt);

	//	}

	//}

}

#endif
