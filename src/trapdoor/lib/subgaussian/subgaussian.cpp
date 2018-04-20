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

#include <NTL/RR.h>
#include <math.h>
#include "subgaussian.h"

namespace lbcrypto {

	template <class Integer, class Vector>
	void LatticeSubgaussianUtility<Integer,Vector>::InverseG(const Integer &u, Vector *output) {

		//create a decomposition vector for the target and the modulus q

			NativeVector uvec(m_k);
			NativeVector qvec(m_k);

			vector<double> target(m_k);

		//decompose the vectors u,q
			Integer uu = u; Integer qq = m_modulus;
			for(size_t i = 0; i<m_k; i++){// ****************4/1/2018 This loop is correct.
				uvec[i] = uu.Mod(m_base); //cout<<uvec[i]<<endl;
				qvec[i] = qq.Mod(m_base); //cout<<qvec[i]<<endl;
				qq = (qq - qvec[i])/m_base;
				uu = (uu - uvec[i])/m_base;
			}

		//compute the c = -1* T^(-1)*uvec

			target[0] = (double)uvec[0].ConvertToInt()/(double)m_base;
			//cout<<target[0]<<endl;
			for(size_t i = 1; i<m_k; i++){//T^(-1)*u *******************4/1/2018 This loop is correct.
				target[i] = (target[i-1] + (double)uvec[i].ConvertToInt())/m_base;
				//cout<<target[i]<<endl;
			}
			for(size_t i = 0; i<m_k; i++){//-u
				target[i] = -1*target[i];
			}

		//Sample the lattice coset centered at 0.
		//v is the coefficients in the sample in basis

			NativeVector v(m_k);
			BcBD(qvec, target, &v);//v is the outputs coefficients in the basis

		//Transform by B_q.

			(*output)[0] = m_base*v[0] + uvec[0] + qvec[0]*v[m_k-1];
			for(size_t i = 1; i<m_k-1; i++){
				(*output)[i] = m_base*v[i] - v[i-1] + v[m_k-1]*qvec[i] + uvec[i];
			}
			(*output)[m_k-1] = qvec[m_k-1]*v[m_k-1] - v[m_k-2] + uvec[m_k-1];
	}

	template <class Integer, class Vector>
	void LatticeSubgaussianUtility<Integer,Vector>::BcBD(const NativeVector &q, const vector<double> &target, NativeVector *v) {

		std::uniform_real_distribution<double> distribution(0.0, 1.0);

	//Run the version of Babai's algorithm on basis D.
	//Also, it returns a coset sample centered at 0.

		vector<double> d(m_k);
		NativeInteger temp;
		//double b_i = pow(double(b), double(k));//b_i = b^k

	//compute the d's*****************This block is correct 4/1/2018

		d[0] = (double)q[0].ConvertToInt()/m_base; //cout<<d[0]<<endl;
		for(unsigned int i = 1; i<m_k; i++){
			d[i] = (d[i-1] + (double)q[i].ConvertToInt())/(double)m_base; //cout<<d[i]<<endl;
		}

	//Sample last coord.

		double prob = target[m_k-1]/d[m_k-1];

		prob = prob - floor(prob);
		temp = (long)(ceil(target[m_k-1]/d[m_k-1]));//temp = z+1

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
			ttemp = target[i] - (double)(*v)[m_k-1].ConvertToInt()*d[i];//update the target from the last coordinate (the only dependency)

			temp = (NativeInteger)(ceil(ttemp - (*v)[m_k-1].ConvertToInt()*d[i]));//upper plane number
			prob = ttemp - (*v)[m_k-1].ConvertToInt()*d[i];
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


}

#endif
