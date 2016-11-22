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
* This code provides the utility for lattice Gaussian sampling (needed by lattice trapdoors).
*/

#include "../crypto/cryptocontext.h"
#include "dgsampling.h"

namespace lbcrypto {

	// Nonspherical sampling that is used to generate perturbation vectors (for spherically distributed premimages in GaussSample)

	void LatticeGaussSampUtility::NonSphericalSample(size_t n, const Matrix<LargeFloat> &sigmaSqrt, double stddev, Matrix<int32_t> *perturbationVector)
	{
		int32_t a(floor(stddev / 2));

		Matrix<LargeFloat> sample([]() { return make_unique<LargeFloat>(); }, sigmaSqrt.GetRows(), 1);

		ContinuousGaussianGenerator(&sample);

		Matrix<LargeFloat> p = sigmaSqrt.Mult(sample);
		RandomizeRound(n, p, a, perturbationVector);

	}

	// Generates a vector using continuous Guassian distribution with mean = 0 and std = 1; uses Box-Muller method

	void LatticeGaussSampUtility::ContinuousGaussianGenerator(Matrix<LargeFloat> *randomVector)
	{

		namespace mp = boost::multiprecision;

		// YSP we use Box-Muller method for generating continuous gaussians included with Boost
		// please note that <> is used; boost::random::normal_distribution<LargeFloat> was causing a compilation error in Linux
		boost::random::normal_distribution<> dgg(0.0, 1.0);

		// gen is a static variable (defined in this file only through #include to largefloat.h)
		for (size_t i = 0; i < randomVector->GetRows(); i++) {
			(*randomVector)(i, 0) = dgg(DistributionGenerator::GetPRNG());
		}
	}

	// Gaussian sampling from lattice for gagdet matrix G and syndrome u ONLY FOR A POWER-OF-TWO MODULUS; Has not been fully tested

	void LatticeGaussSampUtility::GaussSampG(const ILVector2n &u, double sttdev, size_t k,
		DiscreteGaussianGenerator &dgg, Matrix<BigBinaryInteger> *z)
	{
		const BigBinaryInteger& modulus = u.GetParams()->GetModulus();
		for (size_t i = 0; i < u.GetLength(); i++) {

			//initial value of integer syndrome corresponding to component u_i
			BigBinaryInteger t(u.GetValAtIndex(i));

			for (size_t j = 0; j < k; j++) {

				//get the least significant digit of t; used for choosing the right coset to sample from 2Z or 2Z+1
				uint32_t lsb = t.GetDigitAtIndexForBase(1, 2);

				//dgLSB keeps track of the least significant bit of discrete gaussian; initialized to 2 to make sure the loop is entered
				uint32_t dgLSB = 2;
				BigBinaryInteger sampleInteger;

				//checks if the least significant bit of t matches the least signficant bit of a discrete Gaussian sample
				while (dgLSB != lsb)
				{
					sampleInteger = dgg.GenerateInteger(modulus);
					dgLSB = sampleInteger.GetDigitAtIndexForBase(1, 2);
				}

				(*z)(j, i) = sampleInteger;

				//division by 2
				// TODO: Probably incorrect, but this whole function is wrong anyways. Awaiting advice of Daniele
				t = (t.ModSub((*z)(j, i), modulus)) >> 1;
				//t = (t - (*z)(j,i))>>1;

			}

		}

	}

	// Gaussian sampling from lattice for gagdet matrix G and syndrome u and ARBITRARY MODULUS q
	// Algorithm was provided in a personal communication by Daniele Micciancio

	void LatticeGaussSampUtility::GaussSampGq(const ILVector2n &u, double stddev, size_t k, const BigBinaryInteger &q,
		DiscreteGaussianGenerator &dgg, Matrix<int32_t> *z)
	{

		std::vector<double> a(k);  /* can be precomputed, depends only on k */
		std::vector<double> x(k);  /* not essential, used only for clarity */
		std::vector<double> c(k);  /* not essential, used only for clarity */
		std::vector<int32_t> d(k);  /* not essential, used only for clarity */
		std::vector<double> y(k);

		double std3 = stddev / 3;
		std::normal_distribution<double> dggstd3(0.0, std3);

		double stdk = std3 * (pow(2, k) / q.ConvertToDouble());

		a[0] = sqrt(3 + 2.0 / k);
		for (size_t i = 1; i < k; i++)
			a[i] = sqrt(2 + 2.0 / (k - i));

		for (size_t i = 0; i < u.GetLength(); i++) {

			BigBinaryInteger v(u.GetValAtIndex(i));
			int32_t zk, zj;

			for (size_t i = 0; i < k; i++)
				x[i] = dggstd3(DistributionGenerator::GetPRNG());

			y[0] = a[0] * x[0] / 2 + x[1] / a[1];
			for (size_t j = 1; j < k - 1; j++)
				y[j] = y[j - 1] / 2 + a[j] * x[j] / 2 + x[j + 1] / a[j + 1];
			y[k - 1] = y[k - 2] / 2 + a[k - 1] * x[k - 1] / 2;

			zk = dgg.GenerateInteger((pow(2, k) / q.ConvertToDouble())*y[k - 1] - (v.ConvertToDouble() / q.ConvertToDouble()), stdk, u.GetLength()); /* FIX: compute (2^k / q) and  v/q as doubles */;

			for (size_t j = 0; j < k; j++) {
				d[j] = v.GetDigitAtIndexForBase(j + 1, 2) + zk*q.GetDigitAtIndexForBase(j + 1, 2);
				/* How efficient is GetDigitIndexForBase? Implement using left shifts? */
				(*z)(j, i) = d[j];
			}
			c[0] = d[0] / 2.0;

			for (size_t j = 0; j < k - 1; j++) {
				c[j + 1] = (c[j] + d[j + 1]) / 2;
				zj = dgg.GenerateInteger(y[j] - c[j], std3, u.GetLength()); /* generate discrete gaussian sample with mean y[j]-c[j] and standard deviation std3 */
				(*z)(j, i) += zj * 2; //multiplication by 2
				(*z)(j + 1, i) -= zj;
			}
		}

	}

	// Gaussian sampling from lattice for gagdet matrix G and syndrome u and ARBITRARY MODULUS q - Improved algorithm
	// Algorithm was provided in a personal communication by Daniele Micciancio

	void LatticeGaussSampUtility::GaussSampGqV2(const ILVector2n &u, double stddev, size_t k, const BigBinaryInteger &q, int32_t base,
		DiscreteGaussianGenerator &dgg, Matrix<int32_t> *z)
	{
		const BigBinaryInteger& modulus = u.GetParams()->GetModulus();
		//std::cout << "modulus = " << modulus << std::endl; 
		double sigma = stddev / (base + 1);

		// main diagonal of matrix L
		std::vector<double> l(k);
		//upper diagonal of matrix L
		std::vector<double> h(k);

		Matrix<double> a([]() { return make_unique<double>(); }, k, 1);
		Matrix<double> c([]() { return make_unique<double>(); }, k, 1);

		//  set the values of matrix L
		l[0] = sqrt(base*(1 + 1 / k) + 1);
		for (size_t i = 1; i < k; i++)
			l[i] = sqrt(base*(1 + 1 / (k - i)));

		h[0] = 0;
		for (size_t i = 1; i < k; i++)
			h[i] = sqrt(base*(1 - 1 / (k - (i - 1))));

		// c can be pre-computed as it only depends on the modulus
		c(0, 0) = modulus.GetDigitAtIndexForBase(1, base) / base;

		for (size_t i = 1; i < k; i++)
		{
			c(i, 0) = (c(i - 1, 0) + modulus.GetDigitAtIndexForBase(i + 1, base)) / base;
		}

		for (size_t j = 0; j < u.GetLength(); j++)
		{
			BigBinaryInteger v(u.GetValAtIndex(j));

			vector<int32_t> p(k);

			LatticeGaussSampUtility::Perturb(stddev, k, u.GetLength(), l, h, base, dgg, &p);

			// int32_t cast is needed here as GetDigitAtIndexForBase returns an unsigned int
			// when the result is negative, a(0,0) gets values close to 2^32 if the cast is not used
			a(0, 0) = ((int32_t)(v.GetDigitAtIndexForBase(1, base)) - p[0]) / base;

			for (size_t i = 1; i < k; i++)
				a(i, 0) = (a(i - 1, 0) + (int32_t)(v.GetDigitAtIndexForBase(i + 1, base)) - p[i]) / base;

			vector<int32_t> zj(k);

			LatticeGaussSampUtility::SampleC(c, k, u.GetLength(), sigma, dgg, &a, &zj);

			(*z)(0, j) = base*zj[0] + modulus.GetDigitAtIndexForBase(1, base)*zj[k - 1] + v.GetDigitAtIndexForBase(1, base);

			for (size_t i = 1; i < k - 1; i++)
				(*z)(i, j) = base*zj[i] - zj[i - 1] + modulus.GetDigitAtIndexForBase(i + 1, base)*zj[k - 1] + v.GetDigitAtIndexForBase(i + 1, base);

			(*z)(k - 1, j) = modulus.GetDigitAtIndexForBase(k, base)*zj[k - 1] - zj[k - 2] + v.GetDigitAtIndexForBase(k, base);

		}

	}

	// subroutine used by GaussSampGqV2
	// Algorithm was provided in a personal communication by Daniele Micciancio

	void LatticeGaussSampUtility::Perturb(double sigma, size_t k, size_t n,
		const vector<double> &l, const vector<double> &h, int32_t base, DiscreteGaussianGenerator &dgg, vector<int32_t> *p) {

		std::vector<int32_t> z(k);
		double d = 0;

		for (size_t i = 0; i < k; i++)
		{
			z[i] = dgg.GenerateInteger(d / l[i], sigma / l[i], n);
			d = -z[i] * h[i];
		}

		(*p)[0] = (2 * base + 1)*z[0] + base*z[1];
		for (size_t i = 1; i < k - 1; i++)
			(*p)[i] = base*(z[i - 1] + 2 * z[i] + z[i + 1]);
		(*p)[k - 1] = base*(z[k - 2] + 2 * z[k - 1]);

	}

	// subroutine used by GaussSampGqV2
	// Algorithm was provided in a personal communication by Daniele Micciancio

	void LatticeGaussSampUtility::SampleC(const Matrix<double> &c, size_t k, size_t n,
		double sigma, DiscreteGaussianGenerator &dgg, Matrix<double> *a, vector<int32_t> *z)
	{

		(*z)[k - 1] = dgg.GenerateInteger(-(*a)(k - 1, 0) / c(k - 1, 0), sigma / c(k - 1, 0), n);
		*a = *a - ((double)((*z)[k - 1]))*c;

		for (size_t i = 0; i < k - 1; i++)
			(*z)[i] = dgg.GenerateInteger(-(*a)(i, 0), sigma, n);

	}
	
	void ZSampleSigmaP(size_t n, BigBinaryInteger q, double s, double sigma, Matrix<ILVector2n> Tprime, Matrix<int32_t> *perturbationVector, DiscreteGaussianGenerator & dgg) {
		ILVector2n va = Tprime(0, 0)* Tprime.Transpose()(0, 0) + Tprime(0, 1) * Tprime.Transpose()(0, 1);
		ILVector2n vb = Tprime(1, 0) *  Tprime.Transpose()(0, 0) + Tprime(1, 1) *  Tprime.Transpose()(0, 1);
		ILVector2n vd = Tprime(1, 0) *  Tprime.Transpose()(1, 0) + Tprime(1, 1) *  Tprime.Transpose()(1, 1);

		std::vector<double> a, b, d;

		for (int i = 0; i < va.GetLength();i++){
			a.push_back(va.GetValAtIndex(i).ConvertToDouble() * (s * s * (1 - sigma * sigma / (s * s - sigma * sigma))));
			b.push_back(vb.GetValAtIndex(i).ConvertToDouble() * -s *s * sigma * sigma / (s* s - sigma * sigma));
			d.push_back(vd.GetValAtIndex(i).ConvertToDouble() *(s * s * (1 - sigma * sigma / (s * s - sigma * sigma))));
		}

		for (size_t i = 0; i < n * log (q.ConvertToDouble()); i++) {
			(*perturbationVector)(i, 0) = dgg.GenerateInteger(0, sqrt(s * s - sigma * sigma), n);
		}
		  /*
			c =  - sigma / (s * s - sigma * sigma) * Tprime * p2;
		  ZSampleSigma2x2(a,b,d,c, p1,dgg);
		  return p1.insert(p1.end(),p2.begin(),p2.end());
		  */

	}
	void ZSampleSigma2x2(const std::vector<double> & a, const std::vector<double> & b, const std::vector<double> & d, const std::vector<double> & c, Matrix<int32_t>* p1,DiscreteGaussianGenerator & dgg) {
		/*
			q2  = ZSampleF(d,c2);
			c1 = AddPol(c1,MultiplyPol(MultiplyPol(b,d inverse),SubstractPol(q2,c2)));
			q1 = ZSampleF(a-bd inverse b transpose,c1);
			p1 = q1.insert(q1.end(),q2.begin(),q2.end());
		*/

	}
	std::vector<double> ZSampleF(std::vector<double> f, double c, DiscreteGaussianGenerator & dgg,double w,double m,double n) {
		if (f.size() == 1) {
			std::vector<double> p;
			DiscreteFourierTransform dft;
			p.push_back(dgg.GenerateInteger(c, sqrt(dft.InverseTransform(f, w, m)[0]), n));
			return p;
		}
		else {
			/*inverse c
			std::vector<double> f_even,f_odd;
			for(int i=0;i<f.size();f++){
				if(i%2==0){
					f_even.push_back(f[i]);
				}
				else{
					f_odd.push_back(f[i]);
				}
			}
			std::vector<double> r2 = ZSampleF(f_even,c2,dgg,w,m/2,n);
			c1 = AddPol(c1,MultiplyPol(MultiplyPol(f_odd, f_even inverse),SubstractPol(r2,c2))
			r1 = ZSampleF(SubstractPol(f_even,MultiplyPol(MultiplyPol(f_odd,f_odd),f_even inverse,c1,dgg,w,m,n);
			return r1.insert(r1.end(),r2.begin(),r2.end());
			*/
		}
	}

	std::vector<double> MultiplyPol(std::vector<double> A, std::vector<double> B) {
		
		usint size_a = A.size();
		usint size_b = B.size();
		if (size_a < size_b) {
			for (int i = 0;i < size_b - size_a;i++) {
				A.push_back((double)0);
			}
		}
		else {
			if (size_b < size_a) {
				for (int i = 0;i < size_a - size_b;i++) {
					B.push_back((double)0);
				}
			}
		}
		std::vector<double> result;
		for (int j = 0;j < A.size();j++) {
			result.push_back(A[j] * B[j]);
		}
		return result;
	}
	std::vector<double> AddPol(std::vector<double> A, std::vector<double> B) {

		usint size_a = A.size();
		usint size_b = B.size();
		if (size_a < size_b) {
			for (int i = 0;i < size_b - size_a;i++) {
				A.push_back((double)0);
			}
		}
		else {
			if (size_b < size_a) {
				for (int i = 0;i < size_a - size_b;i++) {
					B.push_back((double)0);
				}
			}
		}
		std::vector<double> result;
		for (int j = 0;j < A.size();j++) {
			result.push_back(A[j] + B[j]);
		}
		return result;
	}
	std::vector<double> SubstractPol(std::vector<double> A, std::vector<double> B) {

		usint size_a = A.size();
		usint size_b = B.size();
		if (size_a < size_b) {
			for (int i = 0;i < size_b - size_a;i++) {
				A.push_back((double)0);
			}
		}
		else {
			if (size_b < size_a) {
				for (int i = 0;i < size_a - size_b;i++) {
					B.push_back((double)0);
				}
			}
		}
		std::vector<double> result;
		for (int j = 0;j < A.size();j++) {
			result.push_back(A[j] - B[j]);
		}
		return result;
	}
	
}
