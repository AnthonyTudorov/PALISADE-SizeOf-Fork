/*
Transform-Benchmarking: This code benchmarks the FTT code

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <iostream>
#include <NTL/ZZ.h>
#include "palisade.h"
#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;


#include <iterator>

typedef uint64_t BI;
typedef unsigned __int128 BBI;
typedef std::vector<uint64_t> BGV;

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

BGV primitiveTransform(usint logn, const BI modulus, const BGV& input, const BGV& rootOfUnityTable){
	BI n = (1<<logn);
	BI d2 = modulus*(-2);

	BGV element(n);
	for (usint i = 0; i<n; i++)
		element[i] = mod_mul(input[i], rootOfUnityTable[i], modulus, d2);
	BGV result(n);

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

BGV NTLprimitiveTransform(usint logn, const BI modulus, const BGV& input, const BGV& rootOfUnityTable){
	BI n = (1<<logn);

	BGV element(n);
	for (usint i = 0; i<n; i++)
		element[i] = NTL::MulMod(input[i], rootOfUnityTable[i], modulus);
	BGV result(n);

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
						omegaFactor = NTL::MulMod(omega, result[indexOdd], modulus);

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

BGV NTLprimitiveTransformPrecon(usint logn, const BI modulus, const BGV& input, const BGV& rootOfUnityTable, const BGV& preconTable){
	BI n = (1<<logn);

	BGV element(n);
	for (usint i = 0; i<n; i++)
		element[i] = NTL::MulModPrecon(input[i], rootOfUnityTable[i], modulus, preconTable[i]);
	BGV result(n);

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
						omegaFactor = NTL::MulModPrecon(result[indexOdd], omega, modulus, preconTable[x]);

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

NativeVector precomputedTransform(usint logn, const NativeInteger& modulus, const NativeVector& input, const NativeVector& rootOfUnityTable){
	usint n = (1 << logn);
	NativeInteger mu = ComputeMu<NativeInteger>(modulus);
	NativeVector element(n, modulus);
	for (usint i = 0; i<n; i++)
	  element.at(i)= input.at(i).ModBarrettMul(rootOfUnityTable.at(i), modulus, mu);

	NativeVector result(n);
	result.SetModulus(modulus);

	//reverse coefficients (bit reversal)
	usint msb = GetMSB64(n - 1);
	for (usint i = 0; i < n; i++)
	  result.at(i)= element.at(ReverseBits(i, msb));

	NativeInteger omegaFactor;
	NativeInteger product;
	NativeInteger butterflyPlus;
	NativeInteger butterflyMinus;

	for (usint logm = 1; logm <= logn; logm++)
	{
		for (usint j = 0; j<n; j = j + (1 << logm))
		{
			for (usint i = 0; i < (usint)(1 << (logm-1)); i++)
			{

				usint x = (i << (1+logn-logm));

				const NativeInteger& omega = rootOfUnityTable.at(x);

				usint indexEven = j + i;
				usint indexOdd = j + i + (1 << (logm-1));
				auto oddVal = result.at(indexOdd);
				auto oddMSB = oddVal.GetMSB();
				auto evenVal = result.at(indexEven);

				if (oddMSB > 0)
				{

					if (oddMSB == 1)
						omegaFactor = omega;
					else
						omegaFactor = omega.ModBarrettMul(oddVal, modulus, mu);

					butterflyPlus = evenVal;
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= modulus)
						butterflyPlus -= modulus;

					butterflyMinus = evenVal;
					if (butterflyMinus < omegaFactor)
						butterflyMinus += modulus;
					butterflyMinus -= omegaFactor;

					result.at(indexEven)= butterflyPlus;
					result.at(indexOdd)= butterflyMinus;

				}
				else
				  //result.at(indexOdd)= result.at(indexEven);
				  result[indexOdd] = result[indexEven];

			}

		}
	}
	return result;
}

NativeVector baselineTransform(usint n, const NativeInteger& modulus, const NativeVector& input, const NativeInteger& rootOfUnity){
	NativeVector rootOfUnityTable(n, modulus);
	NativeInteger mu = ComputeMu<NativeInteger>(modulus);
	NativeInteger t(1);

	for (usint i = 0; i<n; i++) {
		rootOfUnityTable.at(i)= t;
		t = t.ModBarrettMul(rootOfUnity, modulus, mu);
	}

	NativeVector element(n, modulus);
	for (usint i = 0; i<n; i++)
		element.at(i)= input.at(i).ModBarrettMul(rootOfUnityTable.at(i), modulus, mu);

	NativeVector result(n);
	result.SetModulus(modulus);

	//reverse coefficients (bit reversal)
	usint msb = GetMSB64(n - 1);
	for (usint i = 0; i < n; i++)
		result.at(i)= element.at(ReverseBits(i, msb));

	NativeInteger omegaFactor;
	NativeInteger product;
	NativeInteger butterflyPlus;
	NativeInteger butterflyMinus;

	for (usint m = 2; m <= n; m = 2 * m)
	{
		for (usint j = 0; j<n; j = j + m)
		{
			for (usint i = 0; i <= m / 2 - 1; i++)
			{

				usint x = (2 * i*n / m);

				const NativeInteger& omega = rootOfUnityTable.at(x);

				usint indexEven = j + i;
				usint indexOdd = j + i + m / 2;

				if (result.at(indexOdd).GetMSB()>0)
				{

					if (result.at(indexOdd).GetMSB() == 1)
						omegaFactor = omega;
					else
						omegaFactor = omega.ModBarrettMul(result.at(indexOdd), modulus, mu);

					butterflyPlus = result.at(indexEven);
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= element.GetModulus())
						butterflyPlus -= element.GetModulus();

					butterflyMinus = result.at(indexEven);
					if (result.at(indexEven) < omegaFactor)
						butterflyMinus += element.GetModulus();
					butterflyMinus -= omegaFactor;

					result.at(indexEven)= butterflyPlus;
					result.at(indexOdd)= butterflyMinus;

				}
				else
				  //result.at(indexOdd)= result.at(indexEven);
				  result[indexOdd] = result[indexEven];

			}

		}
	}

	return result;
}

int main() {

	std::cout << "\n===========BFV TESTS (INNER-PRODUCT-ARBITRARY)===============: " << std::endl;

	//------------------ Setup Parameters ------------------
	usint m = 2048;
	usint phim = 1024;
	PlaintextModulus p = 1964033; // we choose s.t. 2m|p-1 to leverage CRTArb
	NativeInteger modulusP(p);
	PackedEncoding::SetParams(m, p);

	NativeInteger modulusQ("9223372036589678593");
	NativeInteger rootOfUnity("5356268145311420142");
	//NativeInteger delta(modulusQ.DividedBy(modulusP));

	NativeInteger qSmall = 268440577;

	NativeInteger a = 10210121;
	NativeInteger b = 11212133;

	//NativeInteger binv = NTL::PrepMulModPrecon(b.ConvertToInt(), qSmall.ConvertToInt());
	//std::cout << "binv = " << binv << std::endl;
	//long long int temp = NTL::MulModPrecon(a.ConvertToInt(),b.ConvertToInt(),qSmall.ConvertToInt(),binv.ConvertToInt());

	long long int temp = NTL::MulMod(a.ConvertToInt(),b.ConvertToInt(),qSmall.ConvertToInt());

	std::cout << "temp = " << temp << std::endl;

	uint64_t nRep;
	double start, stop;

	DiscreteUniformGeneratorImpl<NativeInteger,NativeVector> dug;
	dug.SetModulus(modulusQ);
	NativeVector x = dug.GenerateVector(phim);

	NativeVector rootOfUnityTable(phim, modulusQ);
	NativeInteger t(1);
	for (usint i = 0; i<phim; i++) {
		rootOfUnityTable.at(i)= t;
		t = t.ModMul(rootOfUnity, modulusQ);
	}

	NativeVector X(m/2), xx(m/2);
	ChineseRemainderTransformFTT<NativeInteger,NativeVector>::ForwardTransform(x, rootOfUnity, m, &X);
	ChineseRemainderTransformFTT<NativeInteger,NativeVector>::InverseTransform(X, rootOfUnity, m, &xx);
	//std::cout << X << std::endl;
	//std::cout << xx << std::endl;

	nRep = 2500;
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		ChineseRemainderTransformFTT<NativeInteger,NativeVector>::ForwardTransform(x, rootOfUnity, m, &X);
	}
	stop = currentDateTime();
	std::cout << " Library Transform: " << (stop-start)/nRep << std::endl;

	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		NativeVector InputToFFT(x);
		usint ringDimensionFactor = rootOfUnityTable.GetLength() / (m / 2);
		NativeInteger mu = ComputeMu<NativeInteger>(x.GetModulus());

		for (usint i = 0; i<m / 2; i++)
			InputToFFT.at(i)= x.at(i).ModBarrettMul(rootOfUnityTable.at(i*ringDimensionFactor), x.GetModulus(), mu);
		NumberTheoreticTransform<NativeInteger,NativeVector>::ForwardTransformIterative(InputToFFT, rootOfUnityTable, m / 2, &X);
	}
	stop = currentDateTime();
	std::cout << " Forward Iterative (with local cache) Transform: " << (stop-start)/nRep << std::endl;

	NativeVector output;
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		output = baselineTransform(phim, modulusQ, x, rootOfUnity);
	}
	stop = currentDateTime();
	std::cout << " Ttran_baseline: " << (stop-start)/nRep << std::endl;
	//std::cout << X << std::endl;
	//std::cout << output << std::endl;

	NativeVector result(1<<10);
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		output = precomputedTransform(10, modulusQ, x, rootOfUnityTable);
	}
	stop = currentDateTime();
	std::cout << " Ttran_precomputed - this is our target: " << (stop-start)/nRep << std::endl;
	//std::cout << X << std::endl;
	//std::cout << output << std::endl;

	nRep = 10000;
	BI q = 9223372036589678593;
	BI z = 5356268145311420142;
	BGV xVec(phim), zVec(phim), outVec;
	BI zi = 1;
	BI d2 = q*(-2);
	for (usint i = 0; i<phim; i++) {
		xVec[i] = x[i].ConvertToInt();
		zVec[i] = zi;
		zi = mod_mul(zi, z, q, d2);
	}
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		outVec = primitiveTransform(10, q, xVec, zVec);
	}
	stop = currentDateTime();
	std::cout << " Ttran_prim: " << (stop-start)/nRep << std::endl;
	//std::cout << X << std::endl;
	std::cout << "[";
	for(usint i = 0; i < phim; i++){
	//	std::cout << outVec[i] << " " ;
	}
	std::cout << "]" << std::endl;

	{

	nRep = 10000;
	BI q =  268440577;
	BI z = 58838461;
	BGV xVec(phim), zVec(phim),  outVec;
	BI zi = 1;
	for (usint i = 0; i<phim; i++) {
		xVec[i] = x[i].ConvertToInt();
		zVec[i] = zi;
		zi = NTL::MulMod(zi, z, q);
	}
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		outVec = NTLprimitiveTransform(10, q, xVec, zVec);
	}
	stop = currentDateTime();
	std::cout << " NTL_Ttran_prim: " << (stop-start)/nRep << std::endl;
	//std::cout << X << std::endl;
	std::cout << "[";
	for(usint i = 0; i < phim; i++){
	//	std::cout << outVec[i] << " " ;
	}
	std::cout << "]" << std::endl;

	}

	{

	nRep = 10000;
	BI q =  268440577;
	BI z = 58838461;
	BGV xVec(phim), zVec(phim), pVec(phim), outVec;
	BI zi = 1;
	for (usint i = 0; i<phim; i++) {
		xVec[i] = x[i].ConvertToInt();
		zVec[i] = zi;
		zi = NTL::MulMod(zi, z, q);
		pVec[i] = NTL::PrepMulModPrecon(zi, q);
	}
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		outVec = NTLprimitiveTransformPrecon(10, q, xVec, zVec, pVec);
	}
	stop = currentDateTime();
	std::cout << " NTL_Ttran_prim: " << (stop-start)/nRep << std::endl;
	//std::cout << X << std::endl;
	std::cout << "[";
	for(usint i = 0; i < phim; i++){
	//	std::cout << outVec[i] << " " ;
	}
	std::cout << "]" << std::endl;

	}

	return 0;
}
