/**
 * @file subgaussian.cpp Provides implementation of subgaussian sampling algorithms
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

#ifndef _LBCRYPTO_LATTICE_SUBGAUSSIAN_CPP
#define _LBCRYPTO_LATTICE_SUBGAUSSIAN_CPP

#include <math.h>
#include "subgaussian.h"

namespace lbcrypto {

	template <class Integer>
	void LatticeSubgaussianUtility<Integer>::Precompute() {

		m_qvec = vector<int64_t>(m_k);

		//decompose the vectors u,q
		Integer qq = m_modulus;
		for(size_t i = 0; i<m_k; i++){// ****************4/1/2018 This loop is correct.
			m_qvec[i] = qq.Mod(m_base).ConvertToInt(); //cout<<qvec[i]<<endl;
			qq = (qq - m_qvec[i])/m_base;
		}

		m_d = vector<float>(m_k);

		//compute the d's*****************This block is correct 4/1/2018
		m_d[0] = (float)m_qvec[0]/(float)m_base; //cout<<d[0]<<endl;
		for(unsigned int i = 1; i<m_k; i++){
			m_d[i] = (m_d[i-1] + (float)m_qvec[i])/(float)m_base;
		}

	}

	template <class Integer>
	void LatticeSubgaussianUtility<Integer>::InverseG(const Integer &u, std::mt19937 &prng, vector<int64_t> *output) const{

		//create a decomposition vector for the target and the modulus q

		vector<int64_t> uvec(m_k);

		vector<float> target(m_k);

		//decompose the vectors u,q
		Integer uu = u;
		for(size_t i = 0; i<m_k; i++){// ****************4/1/2018 This loop is correct.
			uvec[i] = uu.Mod(m_base).ConvertToInt(); //cout<<uvec[i]<<endl;
			uu = (uu - uvec[i])/m_base;
		}

		//compute the target = -1* S^(-1)*uvec

		target[0] = (float)uvec[0]/(float)m_base;
		//cout<<target[0]<<endl;
		for(size_t i = 1; i<m_k; i++){//T^(-1)*u *******************4/1/2018 This loop is correct.
			target[i] = (target[i-1] + (float)uvec[i])/(float)m_base;
			//cout<<target[i]<<endl;
		}
		for(size_t i = 0; i<m_k; i++){//-u
			target[i] = -target[i];
		}

		//Sample the lattice coset centered at 0.
		//x is the coefficients in the sample in basis

		vector<int64_t> x(m_k);
		BcBD(target, prng, &x);//x is the outputs coefficients in the basis

		//Compute S x + u.

		(*output)[0] = m_base*x[0] + uvec[0] + m_qvec[0]*x[m_k-1];
		for(size_t i = 1; i<m_k-1; i++){
			(*output)[i] = m_base*x[i] - x[i-1] + m_qvec[i]*x[m_k-1] + uvec[i];
		}
		(*output)[m_k-1] = m_qvec[m_k-1]*x[m_k-1] - x[m_k-2] + uvec[m_k-1];
	}

	template <class Integer>
	void LatticeSubgaussianUtility<Integer>::BcBD(const vector<float> &target, std::mt19937 &prng, vector<int64_t> *x) const{

		std::uniform_real_distribution<float> distribution(0.0, 1.0);

		//Run the version of Babai's algorithm on basis D.
		//Also, it returns a coset sample centered at 0.

		//Sample last coord.

		float c = target[m_k-1]/m_d[m_k-1];
		int64_t zk = floor(c);
		float prob = c - float(zk);

		if(distribution(prng) <= prob){
			(*x)[m_k-1] = zk + 1;
		}
		else{
			(*x)[m_k-1] = zk;
		}

		//cout<<x[m_k-1]<<endl;

		//Compute the remaining k-1 (independent) coordinates and update the target
		float ti;
		int64_t zi;

		for(int i=m_k-2; i>=0; i--){

			ti = target[i] - (float)(*x)[m_k-1]*m_d[i];//update the target from the last coordinate (the only dependency)
			zi = (int64_t)(floor(ti));//upper plane number
			float prob = ti - float(zi);

			if(distribution(prng) <= prob){
				(*x)[i] = zi + 1;
				//cout<<"top plane"<<endl;
			}
			else{
				(*x)[i] = zi;
				//cout<<"bottom plane"<<endl;
			}
			//cout<<x[i]<<endl;
		}

	}

	void InverseRingVector(const LatticeSubgaussianUtility<BigInteger> &util, const shared_ptr<ILParams> ilParams,
			const Matrix<Poly> &pubElemB, uint32_t seed, Matrix<Poly> *psi){

		std::shared_ptr<std::mt19937> prng;

		prng.reset(new std::mt19937(seed));

		usint n = ilParams->GetCyclotomicOrder() >> 1;
		usint m = pubElemB.GetCols();
		BigInteger q = ilParams->GetModulus();

		uint32_t k = util.GetK();

		vector<int64_t> digits(k);

		//int Max = 0;

		for(usint i=0; i<m; i++)
			for(usint j=0; j<m; j++) {
				(*psi)(j, i).SetValuesToZero();
				if ((*psi)(j, i).GetFormat() != COEFFICIENT){
					(*psi)(j, i).SwitchFormat();
				}
			}

		for (usint i=0; i<m; i++) {
			auto tB = pubElemB(0, i);

			// make sure the transform ring elements are in coefficient domain
			if(tB.GetFormat() != COEFFICIENT){
				tB.SwitchFormat();
			}

			for(size_t j=0; j<n; j++) {

				util.InverseG(tB[j], *prng, &digits);

				/*std::cout << tB[j] << std::endl;
				std::cout << digits<< std::endl;
				std::cin.get();*/

				for(size_t p=0; p<k; p++) {
					//if (abs(digits[p])>Max)
					//	Max = abs(digits[p]);
					if (digits[p] > 0)
						(*psi)(p,i)[j] = digits[p];
					else
						(*psi)(p,i)[j] = q - BigInteger(-digits[p]);
				}

			}

		}

		//std::cout << "maximum = " << Max << std::endl;

	}

	shared_ptr<Matrix<DCRTPoly>> InverseRingVectorDCRT(const std::vector<LatticeSubgaussianUtility<NativeInteger>> &util,
			const Matrix<DCRTPoly> &pubElemB, uint32_t seed){

		std::shared_ptr<std::mt19937> prng;

		prng.reset(new std::mt19937(seed));

		usint m = pubElemB.GetCols();
		usint n = pubElemB(0,0).GetRingDimension();

		auto zero_alloc_poly = DCRTPoly::Allocator(pubElemB(0,0).GetParams(), COEFFICIENT);
		shared_ptr<Matrix<DCRTPoly>> psi(new Matrix<DCRTPoly>(zero_alloc_poly, m, m));

		auto params = pubElemB(0,0).GetParams()->GetParams();

		for (usint i=0; i<m; i++) {
			auto tB = pubElemB(0, i);

			// make sure the transform ring elements are in coefficient domain
			if(tB.GetFormat() != COEFFICIENT){
				tB.SwitchFormat();
			}

			for (size_t u=0; u < tB.GetNumOfElements(); u++) {

				uint32_t k = util[u].GetK();

				vector<int64_t> digits(k);

				for(size_t j=0; j<n; j++) {

					util[u].InverseG(tB.ElementAtIndex(u)[j].ConvertToInt(), *prng, &digits);

					/*std::cout << tB.ElementAtIndex(u)[j].ConvertToInt() << std::endl;
					std::cout << digits<< std::endl;
					std::cin.get();*/

					for (size_t v=0; v < tB.GetNumOfElements(); v++) {

						NativeInteger q = params[v]->GetModulus();

						for(size_t p=0; p<k; p++) {
							if (digits[p] > 0)
								(*psi)(p + u*k,i).ElementAtIndex(v)[j] = digits[p];
							else
								(*psi)(p + u*k,i).ElementAtIndex(v)[j] = q - NativeInteger(-digits[p]);
						}
					}

				}

			}

		}

		return psi;

	}

}

#endif
