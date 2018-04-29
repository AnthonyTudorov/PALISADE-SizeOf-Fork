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

	template <class Integer, class Vector>
	void LatticeSubgaussianUtility<Integer,Vector>::Precompute() {

		m_qvec = vector<int64_t>(m_k);

		//decompose the vectors u,q
		Integer qq = m_modulus;
		for(size_t i = 0; i<m_k; i++){// ****************4/1/2018 This loop is correct.
			m_qvec[i] = qq.Mod(m_base).ConvertToInt(); //cout<<qvec[i]<<endl;
			qq = (qq - m_qvec[i])/m_base;
		}

		m_d = vector<double>(m_k);

		//compute the d's*****************This block is correct 4/1/2018
		m_d[0] = (double)m_qvec[0]/m_base; //cout<<d[0]<<endl;
		for(unsigned int i = 1; i<m_k; i++){
			m_d[i] = (m_d[i-1] + (double)m_qvec[i])/(double)m_base;
		}

	}

	template <class Integer, class Vector>
	void LatticeSubgaussianUtility<Integer,Vector>::InverseG(const Integer &u, vector<int64_t> *output) const{

		//create a decomposition vector for the target and the modulus q

		vector<int64_t> uvec(m_k);

		vector<double> target(m_k);

		//decompose the vectors u,q
		Integer uu = u;
		for(size_t i = 0; i<m_k; i++){// ****************4/1/2018 This loop is correct.
			uvec[i] = uu.Mod(m_base).ConvertToInt(); //cout<<uvec[i]<<endl;
			uu = (uu - uvec[i])/m_base;
		}

		//compute the c = -1* T^(-1)*uvec

		target[0] = (double)uvec[0]/(double)m_base;
		//cout<<target[0]<<endl;
		for(size_t i = 1; i<m_k; i++){//T^(-1)*u *******************4/1/2018 This loop is correct.
			target[i] = (target[i-1] + (double)uvec[i])/m_base;
			//cout<<target[i]<<endl;
		}
		for(size_t i = 0; i<m_k; i++){//-u
			target[i] = -target[i];
		}

		//Sample the lattice coset centered at 0.
		//v is the coefficients in the sample in basis

		vector<int64_t> v(m_k);
		BcBD(target, &v);//v is the outputs coefficients in the basis

		//Transform by B_q.

		(*output)[0] = m_base*v[0] + uvec[0] + m_qvec[0]*v[m_k-1];
		for(size_t i = 1; i<m_k-1; i++){
			(*output)[i] = m_base*v[i] - v[i-1] + v[m_k-1]*m_qvec[i] + uvec[i];
		}
		(*output)[m_k-1] = m_qvec[m_k-1]*v[m_k-1] - v[m_k-2] + uvec[m_k-1];
	}

	template <class Integer, class Vector>
	void LatticeSubgaussianUtility<Integer,Vector>::BcBD(const vector<double> &target, vector<int64_t> *v) const{

		std::uniform_real_distribution<double> distribution(0.0, 1.0);

		//Run the version of Babai's algorithm on basis D.
		//Also, it returns a coset sample centered at 0.

		int64_t temp;

		//Sample last coord.

		double prob = target[m_k-1]/m_d[m_k-1];

		prob = prob - floor(prob);
		temp = (int64_t)(ceil(target[m_k-1]/m_d[m_k-1]));//temp = z+1

		if(distribution(PseudoRandomNumberGenerator::GetPRNG()) <= prob){
			(*v)[m_k-1] = temp;
		}
		else{
			(*v)[m_k-1] = temp - 1;
		}

		//cout<<v[m_k-1]<<endl;

		//Compute the remaining k-1 (independent) coordinates and update the target
		double ttemp;
		for(int i=m_k-2; i>=0; i--){
			ttemp = target[i] - (double)(*v)[m_k-1]*m_d[i];//update the target from the last coordinate (the only dependency)

			temp = (int64_t)(ceil(ttemp - (*v)[m_k-1]*m_d[i]));//upper plane number
			prob = ttemp - (*v)[m_k-1]*m_d[i];
			prob = prob - floor(prob);// ||b_i*|| = 1

			if(distribution(PseudoRandomNumberGenerator::GetPRNG()) <= prob){
				(*v)[i] = temp;
				//cout<<"top plane"<<endl;
			}
			else{
				(*v)[i] = temp - 1;
				//cout<<"bottom plane"<<endl;
			}
			//cout<<v[i]<<endl;
		}

	}

	void InverseRingVector(const LatticeSubgaussianUtility<BigInteger,BigVector> &util, const shared_ptr<ILParams> ilParams, const Matrix<Poly> &pubElemB, Matrix<Poly> *psi){

		usint n = ilParams->GetCyclotomicOrder() >> 1;
		usint m = pubElemB.GetCols();
		BigInteger q = ilParams->GetModulus();

		uint32_t k = util.GetK();

		vector<int64_t> digits(k);

		for (usint i=0; i<m; i++) {
			auto tB = pubElemB(0, i);

			// make sure the transform ring elements are in coefficient domain
			if(tB.GetFormat() != COEFFICIENT){
				tB.SwitchFormat();
			}

			for(size_t j=0; j<n; j++) {

				util.InverseG(tB[j],&digits);

				/*std::cout << tB[j] << std::endl;
				std::cout << digits<< std::endl;
				std::cin.get();*/

				for(size_t p=0; p<k; p++) {
					if (digits[p] > 0)
						(*psi)(p,i)[j] = digits[p];
					else
						(*psi)(p,i)[j] = q - BigInteger(-digits[p]);
				}

			}

		}

	}

}

#endif
