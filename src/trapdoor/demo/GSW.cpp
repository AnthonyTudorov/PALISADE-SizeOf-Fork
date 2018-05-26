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

	GSWScheme<BigInteger,BigVector> scheme;

	uint32_t n = 16;
	uint32_t l = 50;
	uint32_t base = 2;

	double std = 3.19;

	BigInteger q = FirstPrime<BigInteger>(l, 2 * n);

	scheme.Setup(n,base,q,std);
	auto sk = scheme.SecretKeyGen();

	auto c = scheme.Encrypt(BigInteger(1),sk);

	auto p = scheme.Decrypt(c,sk);

	std::cout << "secret key\n" <<  *sk << std::endl;

	std::cout << "plaintext = " << p << std::endl;


	GSWScheme<NativeInteger,NativeVector> schemeNative;

	l = 20;

	NativeInteger qNative = FirstPrime<NativeInteger>(l, 2 * n);

	schemeNative.Setup(n,base,qNative,std);
	auto skNative = schemeNative.SecretKeyGen();

	auto cNative = schemeNative.Encrypt(NativeInteger(1),skNative);

	auto pNative = schemeNative.Decrypt(cNative,skNative);

	std::cout << "secret key\n" <<  *skNative << std::endl;

	std::cout << "plaintext = " << pNative << std::endl;



	return 0;
}





