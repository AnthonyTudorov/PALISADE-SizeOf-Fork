#define PROFILE  //define this to enable PROFILELOG and TIC/TOC

#include "subgaussian/subgaussian.cpp"
#include "subgaussian/gsw.h"
#include "subgaussian/gsw.cpp"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;

template <class Integer, class Vector>
void RunHETests(uint32_t n, uint32_t base, const Integer &q, double std);

int main()
{

	uint32_t n = 16;
	uint32_t l = 50;
	uint32_t base = 2;

	double std = 3.19;

	BigInteger q = FirstPrime<BigInteger>(l, 2 * n);

	std::cout << " ==== POLY =====" << std::endl;

	RunHETests<BigInteger,BigVector>(n,base,q,std);

	l = 30;

	NativeInteger qNative = FirstPrime<NativeInteger>(l, 2 * n);

	std::cout << " ==== NATIVEPOLY =====" << std::endl;

	RunHETests<NativeInteger,NativeVector>(n,base,qNative,std);

	return 0;
}

template <class Integer, class Vector>
void RunHETests(uint32_t n, uint32_t base, const Integer &q, double std) {

	GSWScheme<Integer,Vector> scheme;

	scheme.Setup(n,base,q,std);

	auto sk = scheme.SecretKeyGen();

	auto c = scheme.Encrypt(Integer(1),sk);

	auto cPlus = scheme.EvalAdd(c,c);

	auto cPlus2 = scheme.EvalAdd(cPlus,c);

	auto cMult = scheme.EvalMult(c,c);

	auto cMultByZero = scheme.EvalMult(c,cPlus);

	auto p = scheme.Decrypt(c,sk);

	std::cout << "plaintext = " << p << std::endl;

	auto pPlus = scheme.Decrypt(cPlus,sk);

	std::cout << "plaintext of addition = " << pPlus << std::endl;

	auto pPlus2 = scheme.Decrypt(cPlus2,sk);

	std::cout << "plaintext of triple addition = " << pPlus2 << std::endl;

	auto pMult = scheme.Decrypt(cMult,sk);

	std::cout << "plaintext of multiplication = " << pMult << std::endl;

	auto pMultByZero = scheme.Decrypt(cMultByZero,sk);

	std::cout << "plaintext of multiplication by zero = " << pMultByZero << std::endl;

}


