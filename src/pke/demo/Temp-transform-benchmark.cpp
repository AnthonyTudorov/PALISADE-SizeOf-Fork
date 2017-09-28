/*
Transform-Benchmarking: This code benchmarks the FTT code

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <iostream>
#include "palisade.h"
#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;


#include <iterator>

typedef uint64_t BI;
typedef unsigned __int128 BBI;
typedef std::vector<uint64_t> BV;

inline BI mod_mul(BI a, BI b, BI m, BI d2){
	//BBI ab = (BBI)a*(BBI)b;
	//return (BI)(ab%m);
	// Reduce mod 2*m, delta2 = 2*delta
	BBI c = (BBI)a*(BBI)b; // 126b number
	BBI d = (c >> 64)*d2;  // max 62 + 32 = 94b
	BI e = (BI)(d >> 64)*d2;  // max 30 + 32 = 62b
	BBI z = (BBI)((BI)c) + (BBI)((BI)d) + e; // 64b + 64b + 62b
	while(z >= m){
		z -= m;
	}
	return (BI) z;
}

BV primitiveTransform(usint logn, const BI modulus, const BV& input, const BV& rootOfUnityTable){
	BI n = (1<<logn);
	BI d2 = modulus*(-2);

	BV element(n);
	for (usint i = 0; i<n; i++)
		element[i] = mod_mul(input[i], rootOfUnityTable[i], modulus, d2);
	BV result(n);

	//reverse coefficients (bit reversal)
	for (usint i = 0; i < n; i++)
		result[i] = element[ReverseBits(i, logn)];

	BI omegaFactor;
	BI butterflyPlus;
	BI butterflyMinus;

	for (usint logm = 1; logm <= logn; logm++)
	{
		for (usint j = 0; j<n; j = j + (1 << logm))
		{
			for (usint i = 0; i < (usint)(1 << (logm-1)); i++)
			{

				usint x = (i << (1+logn-logm));

				const BI& omega = rootOfUnityTable[x];

				usint indexEven = j + i;
				usint indexOdd = j + i + (1 << (logm-1));

				if (result[indexOdd] != 0)
				{

					if (result[indexOdd] == 1)
						omegaFactor = omega;
					else
						omegaFactor = mod_mul(omega, result[indexOdd], modulus, d2);

					butterflyPlus = result[indexEven];
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= modulus)
						butterflyPlus -= modulus;

					butterflyMinus = result[indexEven];
					if (result[indexEven] < omegaFactor)
						butterflyMinus += modulus;
					butterflyMinus -= omegaFactor;

					result[indexEven] = butterflyPlus;
					result[indexOdd] = butterflyMinus;
				}
				else
				  result[indexOdd] = result[indexEven];

			}

		}
	}

	return result;
}

BigVector precomputedTransform(usint logn, BigInteger modulus, const BigVector& input, const BigVector& rootOfUnityTable){
	usint n = (1 << logn);
	BigInteger mu = ComputeMu<BigInteger>(modulus);
	BigVector element(n, modulus);
	for (usint i = 0; i<n; i++)
		element.SetValAtIndex(i, input.GetValAtIndex(i).ModBarrettMul(rootOfUnityTable.GetValAtIndex(i), modulus, mu));

	BigVector result(n);
	result.SetModulus(modulus);

	//reverse coefficients (bit reversal)
	usint msb = GetMSB64(n - 1);
	for (usint i = 0; i < n; i++)
		result.SetValAtIndex(i, element.GetValAtIndex(ReverseBits(i, msb)));

	BigInteger omegaFactor;
	BigInteger product;
	BigInteger butterflyPlus;
	BigInteger butterflyMinus;

	for (usint logm = 1; logm <= logn; logm++)
	{
		for (usint j = 0; j<n; j = j + (1 << logm))
		{
			for (usint i = 0; i < (usint)(1 << (logm-1)); i++)
			{

				usint x = (i << (1+logn-logm));

				const BigInteger& omega = rootOfUnityTable.GetValAtIndex(x);

				usint indexEven = j + i;
				usint indexOdd = j + i + (1 << (logm-1));

				if (result.GetValAtIndex(indexOdd).GetMSB()>0)
				{

					if (result.GetValAtIndex(indexOdd).GetMSB() == 1)
						omegaFactor = omega;
					else
						omegaFactor = omega.ModBarrettMul(result.GetValAtIndex(indexOdd), modulus, mu);

					butterflyPlus = result.GetValAtIndex(indexEven);
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= element.GetModulus())
						butterflyPlus -= element.GetModulus();

					butterflyMinus = result.GetValAtIndex(indexEven);
					if (result.GetValAtIndex(indexEven) < omegaFactor)
						butterflyMinus += element.GetModulus();
					butterflyMinus -= omegaFactor;

					result.SetValAtIndex(indexEven, butterflyPlus);
					result.SetValAtIndex(indexOdd, butterflyMinus);

				}
				else
				  //result.SetValAtIndex(indexOdd, result.GetValAtIndex(indexEven));
				  result[indexOdd] = result[indexEven];

			}

		}
	}

	return result;
}

BigVector baselineTransform(usint n, BigInteger modulus, BigVector input, BigInteger rootOfUnity){
	BigVector rootOfUnityTable(n, modulus);
	BigInteger mu = ComputeMu<BigInteger>(modulus);
	BigInteger t(1);

	for (usint i = 0; i<n; i++) {
		rootOfUnityTable.SetValAtIndex(i, t);
		t = t.ModBarrettMul(rootOfUnity, modulus, mu);
	}

	BigVector element(n, modulus);
	for (usint i = 0; i<n; i++)
		element.SetValAtIndex(i, input.GetValAtIndex(i).ModBarrettMul(rootOfUnityTable.GetValAtIndex(i), modulus, mu));

	BigVector result(n);
	result.SetModulus(modulus);

	//reverse coefficients (bit reversal)
	usint msb = GetMSB64(n - 1);
	for (usint i = 0; i < n; i++)
		result.SetValAtIndex(i, element.GetValAtIndex(ReverseBits(i, msb)));

	BigInteger omegaFactor;
	BigInteger product;
	BigInteger butterflyPlus;
	BigInteger butterflyMinus;

	for (usint m = 2; m <= n; m = 2 * m)
	{
		for (usint j = 0; j<n; j = j + m)
		{
			for (usint i = 0; i <= m / 2 - 1; i++)
			{

				usint x = (2 * i*n / m);

				const BigInteger& omega = rootOfUnityTable.GetValAtIndex(x);

				usint indexEven = j + i;
				usint indexOdd = j + i + m / 2;

				if (result.GetValAtIndex(indexOdd).GetMSB()>0)
				{

					if (result.GetValAtIndex(indexOdd).GetMSB() == 1)
						omegaFactor = omega;
					else
						omegaFactor = omega.ModBarrettMul(result.GetValAtIndex(indexOdd), modulus, mu);

					butterflyPlus = result.GetValAtIndex(indexEven);
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= element.GetModulus())
						butterflyPlus -= element.GetModulus();

					butterflyMinus = result.GetValAtIndex(indexEven);
					if (result.GetValAtIndex(indexEven) < omegaFactor)
						butterflyMinus += element.GetModulus();
					butterflyMinus -= omegaFactor;

					result.SetValAtIndex(indexEven, butterflyPlus);
					result.SetValAtIndex(indexOdd, butterflyMinus);

				}
				else
				  //result.SetValAtIndex(indexOdd, result.GetValAtIndex(indexEven));
				  result[indexOdd] = result[indexEven];

			}

		}
	}

	return result;
}

int main() {

#if MATHBACKEND == 6
  	std::cout << "\n===========FV TESTS (INNER-PRODUCT-ARBITRARY)===============: " << std::endl;
	std::cout << "\n=======Not operational for MATHBACKEND 6 at this time=======: " << std::endl;
	return 0;
#else
	std::cout << "\n===========FV TESTS (INNER-PRODUCT-ARBITRARY)===============: " << std::endl;

	//------------------ Setup Parameters ------------------
	usint m = 2048;
	usint phim = 1024;
	usint p = 1964033; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusP(p);
	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	BigInteger modulusQ("9223372036589678593");
	BigInteger rootOfUnity("5356268145311420142");
	BigInteger delta(modulusQ.DividedBy(modulusP));

	uint64_t nRep;
	double start, stop;

	BigVector x(phim, modulusQ);
	for(usint i=0; i<phim; i++){
		x.SetValAtIndex(i, BigInteger(i));
	}
	BigVector X, xx;
	X = ChineseRemainderTransformFTT<BigInteger,BigVector>::GetInstance()
			.ForwardTransform(x, rootOfUnity, m);
	xx = ChineseRemainderTransformFTT<BigInteger,BigVector>::GetInstance()
			.InverseTransform(X, rootOfUnity, m);
	std::cout << X << std::endl;
	std::cout << xx << std::endl;

	nRep = 1000;
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		X = ChineseRemainderTransformFTT<BigInteger,BigVector>::GetInstance()
				.ForwardTransform(x, rootOfUnity, m);
	}
	stop = currentDateTime();
	std::cout << " Ttran: " << (stop-start)/nRep << std::endl;

	BigVector output;
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		output = baselineTransform(phim, modulusQ, x, rootOfUnity);
	}
	stop = currentDateTime();
	std::cout << " Ttran_baseline: " << (stop-start)/nRep << std::endl;
	std::cout << X << std::endl;
	std::cout << output << std::endl;

	BigVector rootOfUnityTable(phim, modulusQ);
	BigInteger t(1);
	for (usint i = 0; i<phim; i++) {
		rootOfUnityTable.SetValAtIndex(i, t);
		t = t.ModMul(rootOfUnity, modulusQ);
	}

	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		output = precomputedTransform(10, modulusQ, x, rootOfUnityTable);
	}
	stop = currentDateTime();
	std::cout << " Ttran_precomputed: " << (stop-start)/nRep << std::endl;
	std::cout << X << std::endl;
	std::cout << output << std::endl;

	nRep = 10000;
	BI q = 9223372036589678593;
	BI z = 5356268145311420142;
	BV xVec(phim), zVec(phim), outVec;
	BI zi = 1;
	BI d2 = q*(-2);
	for (usint i = 0; i<phim; i++) {
		xVec[i] = i;
		zVec[i] = zi;
		zi = mod_mul(zi, z, q, d2);
	}
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		outVec = primitiveTransform(10, q, xVec, zVec);
	}
	stop = currentDateTime();
	std::cout << " Ttran_prim: " << (stop-start)/nRep << std::endl;
	std::cout << X << std::endl;
	std::cout << "[";
	for(usint i = 0; i < phim; i++){
		std::cout << outVec[i] << " " ;
	}
	std::cout << "]" << std::endl;

	return 0;
#endif //#ifdef MATHBACKEND == 6
}
