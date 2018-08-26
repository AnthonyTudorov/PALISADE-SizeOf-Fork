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

	auto cMult = scheme.EvalMult(c,c);

	auto p = scheme.Decrypt(c,sk);

	auto pMult = scheme.Decrypt(cMult,sk);

	//std::cout << "secret key\n" <<  *sk << std::endl;

	std::cout << " ==== POLY =====" << std::endl;

	std::cout << "plaintext = " << p << std::endl;

	std::cout << "plaintext of multiplication = " << pMult << std::endl;


	GSWScheme<NativeInteger,NativeVector> schemeNative;

	l = 30;

	NativeInteger qNative = FirstPrime<NativeInteger>(l, 2 * n);

	schemeNative.Setup(n,base,qNative,std);
	auto skNative = schemeNative.SecretKeyGen();

	auto cNative = schemeNative.Encrypt(NativeInteger(1),skNative);

	auto cNativePlus = schemeNative.EvalAdd(cNative,cNative);

	auto cNativePlus2 = schemeNative.EvalAdd(cNativePlus,cNative);

	auto cNativeMult = schemeNative.EvalMult(cNative,cNative);

	auto pNative = schemeNative.Decrypt(cNative,skNative);

	auto pNativePlus = schemeNative.Decrypt(cNativePlus,skNative);

	auto pNativePlus2 = schemeNative.Decrypt(cNativePlus2,skNative);

	auto pNativeMult = schemeNative.Decrypt(cNativeMult,skNative);

	//std::cout << "secret key\n" <<  *skNative << std::endl;

	std::cout << " ==== NATIVEPOLY =====" << std::endl;

	std::cout << "plaintext = " << pNative << std::endl;

	std::cout << "plaintext of addition = " << pNativePlus << std::endl;

	std::cout << "plaintext of triple addition = " << pNativePlus2 << std::endl;

	std::cout << "plaintext of multiplication = " << pNativeMult << std::endl;

	return 0;
}





