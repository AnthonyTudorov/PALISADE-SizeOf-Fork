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
	
	void LatticeGaussSampUtility::ZSampleSigmaP(size_t n, BigBinaryInteger q, double s, double sigma, 
		const Matrix<ILVector2n> &Tprime, Matrix<int32_t> *perturbationVector, const DiscreteGaussianGenerator & dgg) {

		Matrix<ILVector2n> Tprime0 = Tprime.ExtractRow(0);
		Matrix<ILVector2n> Tprime1 = Tprime.ExtractRow(1);
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

		size_t k = Tprime.GetRows();
		Matrix<int32_t> p2ZVector([]() { return make_unique<int32_t>(); }, n*k, 1);

		//this loop can be replaced with Peikert's and Yao's inversion methods - more efficient
		for (size_t i = 0; i < n * k; i++) {
			p2ZVector(i, 0) = dgg.GenerateInteger(0, sqrt(s * s - sigma * sigma), n);
		}

		//create k ring elements in coefficient representation
		Matrix<ILVector2n> p2 = SplitInt32AltIntoILVector2nElements(p2ZVector, n,va.GetParams());

		//now converting to evaluation representation before multiplication
		p2.SwitchFormat();

		//the dimension is 2x1 - a vector of 2 ring elements
		Matrix<ILVector2n> Tp2 = Tprime * p2;

		//change to coefficient representation before converting to field elements
		Tp2(0, 0).SwitchFormat();
		Tp2(1, 0).SwitchFormat();

		Matrix<Field2n> c([]() { return make_unique<Field2n>(); }, 2, 1);

		c(0, 0) = Field2n(Tp2(0, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));
		c(1, 0) = Field2n(Tp2(1, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));

		Matrix<int32_t> p1ZVector([]() { return make_unique<int32_t>(); }, n*2, 1);

		ZSampleSigma2x2(a, b, d, c, &p1ZVector, dgg);

		for (size_t i = 0; i < 2*n; i++) {
			(*perturbationVector)(i, 0) = p1ZVector(i,0);
		}

		for (size_t i = 0; i < k * n; i++) {
			(*perturbationVector)(i+2*n, 0) = p2ZVector(i, 0);
		}

	}

	void LatticeGaussSampUtility::ZSampleSigma2x2(const Field2n &a, const Field2n &b,
		const Field2n &d, const Matrix<Field2n> &c, Matrix<int32_t>* q,const DiscreteGaussianGenerator & dgg) {

			Matrix<int32_t> q2Int  = ZSampleF(d,c(1,0),dgg);
			Field2n q2(q2Int);
			
			Field2n q2Minusc2 = q2 - c(1, 0);
			//Convert to DFT represenation prior to multiplication
			q2Minusc2.SwitchFormat();

			Field2n product = b * d.Inverse() * q2Minusc2;
			//Convert the product to coefficient representation
			product.SwitchFormat();
			
			//Computes c1 in DFT format
			Field2n c1 = c(0, 0) + product;

			Matrix<int32_t> q1Int = ZSampleF(a - b*d.Inverse()*b.Transpose(), c1, dgg);

			for (size_t i = 0; i < q1Int.GetRows(); i++) {
				(*q)(i, 0) = q1Int(i,0);
			}

			for (size_t i = 0; i < q2Int.GetRows(); i++) {
				(*q)(i + q1Int.GetRows(), 0) = q2Int(i, 0);
			}

	}

	//f is in DFT representation
	//c is in Coefficient representation
	Matrix<int32_t> LatticeGaussSampUtility::ZSampleF(const Field2n &f, const Field2n &c,
		const DiscreteGaussianGenerator &dgg) {

	}

	
}
