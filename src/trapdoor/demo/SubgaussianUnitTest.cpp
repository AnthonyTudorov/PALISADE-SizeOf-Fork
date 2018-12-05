#define PROFILE  //define this to enable PROFILELOG and TIC/TOC

//native libs
//#include <sys/resource.h>
#include <math.h>
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <fstream>
//created files
#include "subgaussian/inv_g.cpp"
#include "subgaussian/BcBD.cpp"

#include "utils/debug.h"

#include "subgaussian/subgaussian.h"

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

	long b = 2; long q = 1073741827; long k = (long)ceil(log2(q)/log2(b));
	NTL::Vec<long> output; output.SetLength(k);

	long u = pow(3,5);

	const size_t count = 10000;

	TIC(t1); //start timer for total time
	for (size_t i = 0; i<count; i++)
		inv_g(b, q, u, k, output);
	timeEval = TOC_US(t1);

	std::cout << "Old impl sampling time: " << timeEval/count << " microseconds" << std::endl;

	LatticeSubgaussianUtility<NativeInteger> sampler(b,q,k);

	vector<int64_t> nativeOutput(k);

	TIC(t1); //start timer for total time
	for (size_t i = 0; i<count; i++)
		sampler.InverseG(u, PseudoRandomNumberGenerator::GetPRNG(),&nativeOutput);
	timeEval = TOC_US(t1);

	std::cout << "PALISADE impl sampling time: " << timeEval/count << " microseconds" << std::endl;

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

BigInteger bigModulus = BigInteger("3079705401285115676503558331198");
long kBig = (long)ceil(log2(bigModulus.ConvertToDouble())/log2(b));

LatticeSubgaussianUtility<BigInteger> samplerBig(b,bigModulus,kBig);

vector<int64_t> nativeOutputBig(kBig);

TIC(t1); //start timer for total time
for (size_t i = 0; i<count; i++)
	samplerBig.InverseG(bigModulus>>2, PseudoRandomNumberGenerator::GetPRNG(), &nativeOutputBig);
timeEval = TOC_US(t1);

std::cout << "PALISADE impl sampling time: " << timeEval/count << " microseconds" << std::endl;

//test the output
BigInteger testBig1 = 0; BigInteger bBig_i1 = 1;
cout<<"********************** output = "<<endl;
	for(int i = 0; i<kBig; i++){
		testBig1 +=BigInteger(nativeOutputBig[i])*bBig_i1;
		bBig_i1 = bBig_i1*BigInteger(b);
		std::cout<<nativeOutputBig[i]<<std::endl;
	}

cout<<"g^t * output 2 = "<<testBig1<<endl;

return 0;
}

// 3/23/2018: We must change the code in BcB to update the target each step!
// 4/1/2018: The code works! Now we must change the modular arithmetic to use the residues {-q/2, ... , 0, 1, ... , q/2}. (I'm not sure if this matters.)