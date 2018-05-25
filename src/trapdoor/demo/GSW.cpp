#define PROFILE  //define this to enable PROFILELOG and TIC/TOC

#include "subgaussian/subgaussian.cpp"
#include "subgaussian/gsw.h"
#include "subgaussian/gsw.cpp"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;


int main()
{

	GSWScheme<NativeInteger,NativeVector> scheme;

	uint32_t n = 512;
	uint32_t m = 100;
	uint32_t l = 30;

	double std = 3.19;

	NativeInteger q = FirstPrime<NativeInteger>(l, 2 * n);

	scheme.Setup(n,l,m,q,std);
	auto sk = scheme.SecretKeyGen();

	auto c = scheme.Encrypt(NativeInteger(1),sk);

	std::cout << *sk << std::endl;


	return 0;
}





