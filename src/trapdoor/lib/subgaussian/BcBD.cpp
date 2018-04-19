#include <NTL/RR.h>
#include <math.h>
#include <iostream>

using namespace std;


void BcBD(const unsigned long& b, const NTL::Vec<long>& q, const NTL::Vec<double>& target, NTL::Vec<long>& v, const unsigned long& k){
//Run the version of Babai's algorithm on basis D. 
//Also, it returns a coset sample centered at 0.

	NTL::Vec<double> d; d.SetLength(k);
	long temp;
	//double b_i = pow(double(b), double(k));//b_i = b^k

//compute the d's*****************This block is correct 4/1/2018
	
	d[0] = (double)q[0]/b; //cout<<d[0]<<endl;
	for(unsigned int i = 1; i<k; i++){
	d[i] = (d[i-1] + (double)q[i])/(double)b; //cout<<d[i]<<endl; 
	}

//Sample last coord. 

	NTL::RR prob = NTL::RR(target[k-1])/NTL::RR(d[k-1]); prob = prob - NTL::floor(prob); 
	temp = (long)(ceil(target[k-1]/d[k-1]));//temp = z+1


	if(NTL::random_RR() <= prob){
		v[k-1] = temp;
	}
	else{
		v[k-1] = temp - 1;	
	}
	
	cout<<v[k-1]<<endl;

//Compute the remaining k-1 (independent) coordinates and update the target 
double ttemp;
	for(int i=k-2; i>=0; i--){
		ttemp = target[i] - (double)v[k-1]*d[i];//update the target from the last coordinate (the only dependency)
		
		temp = (long)(ceil(ttemp - v[k-1]*d[i]));//upper plane number
		prob = (NTL::conv<NTL::RR>(ttemp) - NTL::conv<NTL::RR>(v[k-1]*d[i])); prob = prob - NTL::floor(prob);// ||b_i*|| = 1

		if(NTL::random_RR() <= prob){
			v[i] = temp;
			//cout<<"top plane"<<endl;	
		}
		else{
			v[i] = temp - 1;
			//cout<<"bottom plane"<<endl;		
		}
		cout<<v[i]<<endl;
	}

}

