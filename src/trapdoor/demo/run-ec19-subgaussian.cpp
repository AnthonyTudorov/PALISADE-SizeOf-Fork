#define PROFILE  //define this to enable PROFILELOG and TIC/TOC

//native libs
//#include <sys/resource.h>
#include <math.h>
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <fstream>

#include "utils/debug.h"

#include "subgaussian/subgaussian.h"

using namespace std;
using namespace lbcrypto;

void RunFigure1();

int main(){

	RunFigure1();

	
	return 0;
}

void RunFigure1() {

	TimeVar t1; //for TIC TOC

	double timeEval;

	usint n = 1024;
	size_t kRes = 60;

	NativeInteger firstInteger = FirstPrime<NativeInteger>(kRes, 2 * n);
	firstInteger -= (int64_t)(2*n)*((int64_t)(1)<<(kRes/3));
	NativeInteger q = NextPrime<NativeInteger>(firstInteger, 2 * n);
	NativeInteger rootOfUnity(RootOfUnity<NativeInteger>(2 * n, q));

	const size_t count = 100000;

	DiscreteUniformGeneratorImpl<NativeVector> dug;
	dug.SetModulus(q);

	NativeVector randomVector = dug.GenerateVector(count);

	for (size_t b = 2; b < 1073741825; b = b*2)
	{
		size_t k = (long)ceil(log2(q.ConvertToDouble())/log2(b));

		LatticeSubgaussianUtility<NativeInteger> sampler(b,q,k);

		vector<int64_t> nativeOutput(k);

		TIC(t1); //start timer for total time
		for (size_t i = 0; i<count; i++)
			sampler.InverseG(randomVector[i], PseudoRandomNumberGenerator::GetPRNG(),&nativeOutput);
		timeEval = TOC_US(t1);

		std::cout << "log2(base): " << log2(b) << "; Number of samples: " << 1e6/timeEval*count << std::endl;
	}

	return;

}

