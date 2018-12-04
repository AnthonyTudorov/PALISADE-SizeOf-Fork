#include <math.h>
#include <iostream>
#include "BcBD.h"
#include <NTL/vector.h>
#include <NTL/matrix.h>

//The purpose of this code is to implement a randomized inverse g function. 
using namespace std;

void inv_g(const unsigned long& b, const unsigned long& q, const unsigned long& u, const unsigned long& k, NTL::Vec<long>& output /*long *output*/){ 
//create a decomposition vector for the target and the modulus q

	NTL::Vec<long> uvec; uvec.SetLength(k); NTL::Vec<long> qvec; qvec.SetLength(k); 
	NTL::Vec<double> target; target.SetLength(k);

//decompose the vectors u,q
	long uu = u; long qq = q; 
	for(unsigned int i = 0; i<k; i++){// ****************4/1/2018 This loop is correct.
		uvec[i] = uu % b; //cout<<uvec[i]<<endl;
		qvec[i] = qq % b; //cout<<qvec[i]<<endl;
		qq = (qq - qvec[i])/b;
		uu = (uu - uvec[i])/b;
	}

//compute the c = -1* T^(-1)*uvec
 
	target[0] = (double)uvec[0]/(double)b;
	//cout<<target[0]<<endl;
	for(unsigned int i = 1; i<k; i++){//T^(-1)*u *******************4/1/2018 This loop is correct.
		target[i] = (target[i-1] + (double)uvec[i])/b;
		//cout<<target[i]<<endl;
	}
	for(unsigned int i = 0; i<k; i++){//-u
		target[i] = -1*target[i];
	}


//Sample the lattice coset centered at 0. 
//v is the coefficients in the sample in basis
 
	NTL::Vec<long> v; v.SetLength(k);
	BcBD(b, qvec, target, v, k);//v is the outputs coefficients in the basis

//Transform by B_q. 

	output[0] = b*v[0] + uvec[0] + qvec[0]*v[k-1];
	for(unsigned int i = 1; i<k-1; i++){
		output[i] = b*v[i] - v[i-1] + v[k-1]*qvec[i] + uvec[i];
	}
	output[k-1] = qvec[k-1]*v[k-1] - v[k-2] + uvec[k-1];
}
