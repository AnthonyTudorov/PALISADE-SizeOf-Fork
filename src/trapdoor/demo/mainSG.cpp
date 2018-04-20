#define PROFILE  //define this to enable PROFILELOG and TIC/TOC

//native libs
//#include <sys/resource.h>
#include <math.h>
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <fstream>
//created files
#include "subgaussian/inv_g.h"
#include "subgaussian/BcBD.h"

#include "utils/debug.h"

#include "subgaussian/subgaussian.cpp"

//NTL

#include <NTL/ZZ.h>
#include <NTL/vector.h>
#include <NTL/matrix.h>
#include <NTL/RR.h>

using namespace std;
using namespace lbcrypto;

int main(){

	TimeVar t1; //for TIC TOC

	double timeEval;

	long b = 3; long q = 10000000; long k = (long)ceil(log2(q)/log2(b)); 
	NTL::Vec<long> output; output.SetLength(k);

	long u = 699211;

	TIC(t1); //start timer for total time
	inv_g(b, q, u, k, output);
	timeEval = TOC_US(t1);

	std::cout << "Old impl sampling time: " << timeEval << " microseconds" << std::endl;
	
	LatticeSubgaussianUtility<NativeInteger,NativeVector> sampler(b,q,k);

	vector<int64_t> nativeOutput(k);

	TIC(t1); //start timer for total time
	sampler.InverseG(u, &nativeOutput);
	timeEval = TOC_US(t1);

	std::cout << "PALISADE impl sampling time: " << timeEval << " microseconds" << std::endl;

	NTL::RR a = NTL::RR(10.0/27); NTL::RR c = NTL::RR(19.0/27);

//test the output
long test = 0; long b_i = 1;
cout<<"********************** output = "<<endl;
	for(int i = 0; i<k; i++){
		test += output[i]*b_i;
		b_i = b_i*b;
		cout<<output[i]<<endl;
	}

cout<<"g^t * output = "<<test<<endl;

//test the output
int64_t test1 = 0; int64_t b_i1 = 1;
cout<<"********************** output = "<<endl;
	for(int i = 0; i<k; i++){
		test1 +=nativeOutput[i]*b_i1;
		b_i1 = b_i1*b;
		std::cout<<nativeOutput[i]<<std::endl;
	}

cout<<"g^t * output 2 = "<<test1<<endl;
return 0;
}

// 3/23/2018: We must change the code in BcB to update the target each step!
// 4/1/2018: The code works! Now we must change the modular arithmetic to use the residues {-q/2, ... , 0, 1, ... , q/2}. (I'm not sure if this matters.)
