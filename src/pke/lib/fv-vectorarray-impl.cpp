/*
* @file fv-dcrtpoly-impl.cpp - vector array implementation for the FV scheme.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "cryptocontext.h"
#include "fv.cpp"

namespace lbcrypto {

// Parameter generation for FV-RNS
template <>
bool LPAlgorithmParamsGenFV<DCRTPoly>::ParamsGen(shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount) const
{

	if (!cryptoParams)
		return false;

	const shared_ptr<LPCryptoParametersFV<DCRTPoly>> cryptoParamsFV = std::dynamic_pointer_cast<LPCryptoParametersFV<DCRTPoly>>(cryptoParams);

	double sigma = cryptoParamsFV->GetDistributionParameter();
	double alpha = cryptoParamsFV->GetAssuranceMeasure();
	double hermiteFactor = cryptoParamsFV->GetSecurityLevel();
	double p = cryptoParamsFV->GetPlaintextModulus().ConvertToDouble();
	uint32_t r = cryptoParamsFV->GetRelinWindow();

	//Bound of the Gaussian error polynomial
	double Berr = sigma*sqrt(alpha);

	//Bound of the key polynomial
	double Bkey;

	//supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParamsFV->GetMode() == RLWE)
		Bkey = sigma*sqrt(alpha);
	else
		Bkey = 1;

	//expansion factor delta
	auto delta = [](uint32_t n) -> double { return sqrt(n); };

	//norm of fresh ciphertext polynomial
	auto Vnorm = [&](uint32_t n) -> double { return Berr*(1+2*delta(n)*Bkey);  };

	//RLWE security constraint
	auto nRLWE = [&](double q) -> double { return log2(q / sigma) / (4 * log2(hermiteFactor));  };

	//initial values
	uint32_t n = 512;
	double q = 0;

	//only public key encryption and EvalAdd (optional when evalAddCount = 0) operations are supported
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	if ((evalMultCount == 0) && (keySwitchCount == 0)) {

		//Correctness constraint
		auto qFV = [&](uint32_t n) -> double { return p*(2*((evalAddCount+1)*Vnorm(n) + evalAddCount*p) + p);  };

		//initial value
		q = qFV(n);

		while (nRLWE(q) > n) {
			n = 2 * n;
			q = qFV(n);
		}

	}
	// this case supports re-encryption and automorphism w/o any other operations
	else if ((evalMultCount == 0) && (keySwitchCount > 0) && (evalAddCount == 0)) {

		//base for relinearization
		double w = pow(2, r);

		//Correctness constraint
		auto qFV = [&](uint32_t n, double qPrev) -> double { return p*(2*(Vnorm(n) + keySwitchCount*delta(n)*(floor(log2(qPrev) / r) + 1)*w*Berr) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q
		//changes the requirement for n, which is rare but still theortically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qFV(n, qPrev);
				qPrev = q;
			}

			q = qFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qFV(n, qPrev);
			}

		}

	}
	//Only EvalMult operations are used in the correctness constraint
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	else if ((evalAddCount == 0) && (evalMultCount > 0) && (keySwitchCount == 0))
	{

		//base for relinearization
		double w = pow(2, r);

		//function used in the EvalMult constraint
		auto epsilon1 = [&](uint32_t n) -> double { return 4 / (delta(n)*Bkey);  };

		//function used in the EvalMult constraint
		auto C1 = [&](uint32_t n) -> double { return (1 + epsilon1(n))*delta(n)*delta(n)*p*Bkey;  };

		//function used in the EvalMult constraint
		auto C2 = [&](uint32_t n, double qPrev) -> double { return delta(n)*delta(n)*Bkey*(Bkey + p*p) + delta(n)*(floor(log2(qPrev) / r) + 1)*w*Berr;  };

		//main correctness constraint
		auto qFV = [&](uint32_t n, double qPrev) -> double { return p*(2 * (pow(C1(n), evalMultCount)*Vnorm(n) + evalMultCount*pow(C1(n), evalMultCount - 1)*C2(n, qPrev)) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q
		//changes the requirement for n, which is rare but still theoretically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qFV(n, qPrev);
				qPrev = q;
			}

			q = qFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qFV(n, qPrev);
			}

		}

	}

	size_t dcrtBits = 45;
	size_t size = ceil((floor(log2(q - 1.0)) + 2.0) / (double)dcrtBits);

	vector<native_int::BigInteger> moduli(size);
	vector<native_int::BigInteger> roots(size);

	moduli[0] = FirstPrime<native_int::BigInteger>(dcrtBits, 2 * n);
	roots[0] = RootOfUnity<native_int::BigInteger>(2 * n, moduli[0]);

	for (size_t i = 1; i < size; i++)
	{
		moduli[i] = NextPrime<native_int::BigInteger>(moduli[i-1], 2 * n);
		roots[i] = RootOfUnity<native_int::BigInteger>(2 * n, moduli[i]);
	}

	//if (size > 1) {
	//	moduli[size-1] = FirstPrime<native_int::BigInteger>(dcrtBits-1, 2 * n);
	//	roots[size-1] = RootOfUnity<native_int::BigInteger>(2 * n, moduli[size-1]);
	//}

	std::vector<double> precomputedDCRTDecryptionTable(size);

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(2 * n, moduli, roots));

	// second set of DCRT parameters

	std::cout << "starting paramsS generation" << std::endl;

	size_t sizeS = size + 1;

	vector<native_int::BigInteger> moduliS(sizeS);
	vector<native_int::BigInteger> rootsS(sizeS);

	moduliS[0] = NextPrime<native_int::BigInteger>(moduli[size-1], 2 * n);
	rootsS[0] = RootOfUnity<native_int::BigInteger>(2 * n, moduliS[0]);

	for (size_t i = 1; i < sizeS; i++)
	{
		moduliS[i] = NextPrime<native_int::BigInteger>(moduliS[i-1], 2 * n);
		rootsS[i] = RootOfUnity<native_int::BigInteger>(2 * n, moduliS[i]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsS(new ILDCRTParams<BigInteger>(2 * n, moduliS, rootsS));

	std::cout << "finished paramsS generation" << std::endl;

	const BigInteger modulusQ = params->GetModulus();

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduli[i].ConvertToInt());
		precomputedDCRTDecryptionTable[i] = ((modulusQ.DividedBy(qi)).ModInverse(qi) * cryptoParamsFV->GetPlaintextModulus()).Mod(qi).ConvertToDouble()/qi.ConvertToDouble();
		//std::cout << precomputedDCRTDecryptionTable[i] << std::endl;
	}

	cryptoParamsFV->SetDCRTParamsS(paramsS);

	std::cout << "Generated parameters for S" << std::endl;

	cryptoParamsFV->SetDCRTPolyDecryptionTable(precomputedDCRTDecryptionTable);

	cryptoParamsFV->SetElementParams(params);

	const BigInteger deltaBig = params->GetModulus().DividedBy(cryptoParamsFV->GetPlaintextModulus());

	std::cout << deltaBig << std::endl;

	cryptoParamsFV->SetDelta(deltaBig);

	std::vector<native_int::BigInteger> precomputedDCRTDeltaTable(size);

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduli[i].ConvertToInt());
		BigInteger deltaI = deltaBig.Mod(qi);
		precomputedDCRTDeltaTable[i] = native_int::BigInteger(deltaI.ConvertToInt());
		//std::cout << "qi=" << qi << std::endl;
	}

	cryptoParamsFV->SetDCRTPolyDeltaTable(precomputedDCRTDeltaTable);

	std::vector<native_int::BigInteger> qInv(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		qInv[vi] = divBy.ModInverse(qi).Mod(qi).ConvertToInt();
	}

	cryptoParamsFV->SetDCRTPolyInverseTable(qInv);

	std::cout << "generated the inverse table" << std::endl;

	std::vector<native_int::BigInteger> qDecryptionInt(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		BigInteger quotient = (divBy.ModInverse(qi))*(cryptoParamsFV->GetPlaintextModulus())/qi;
		qDecryptionInt[vi] = quotient.Mod(cryptoParamsFV->GetPlaintextModulus()).ConvertToInt();
	}

	cryptoParamsFV->SetDCRTPolyDecryptionIntTable(qDecryptionInt);

	std::vector<std::vector<native_int::BigInteger>> qDivqiModsi(sizeS);
	for( usint newvIndex = 0 ; newvIndex < sizeS; newvIndex++ ) {
		BigInteger si = BigInteger(moduliS[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < size; vIndex++ ) {
			BigInteger qi = BigInteger(moduli[vIndex].ConvertToInt());
			BigInteger divBy = modulusQ / qi;
			qDivqiModsi[newvIndex].push_back(divBy.Mod(si).ConvertToInt());
		}
	}

	cryptoParamsFV->SetDCRTPolyqDivqiModsiTable(qDivqiModsi);

	std::cout << "generated the qDivquModsi table" << std::endl;

	std::vector<native_int::BigInteger> qModsi(sizeS);
	for( usint vi = 0 ; vi < sizeS; vi++ ) {
		BigInteger si = BigInteger(moduliS[vi].ConvertToInt());
		qModsi[vi] = modulusQ.Mod(si).ConvertToInt();
	}

	cryptoParamsFV->SetDCRTPolyqModsiTable(qModsi);

	std::cout << "generated the qModsi table" << std::endl;


	vector<native_int::BigInteger> moduliExpanded(size + sizeS);
	vector<native_int::BigInteger> rootsExpanded(size + sizeS);

	// populate moduli for CRT basis Q
	for (size_t i = 0; i < size; i++ ) {
		moduliExpanded[i] = moduli[i];
		rootsExpanded[i] = roots[i];
	}

	// populate moduli for CRT basis S
	for (size_t i = 0; i < sizeS; i++ ) {
		moduliExpanded[size + i] = moduliS[i];
		rootsExpanded[size + i] = rootsS[i];
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsExpanded(new ILDCRTParams<BigInteger>(2 * n, moduliExpanded, rootsExpanded));

	cryptoParamsFV->SetDCRTParamsQS(paramsExpanded);

	std::vector<double> precomputedDCRTMultFloatTable(size + sizeS);

	const BigInteger modulusS = paramsS->GetModulus();
	const BigInteger modulusQS = paramsExpanded->GetModulus();

	const BigInteger &modulusP = cryptoParamsFV->GetPlaintextModulus();

	for (size_t i = 0; i < size + sizeS; i++){
		BigInteger qi = BigInteger(moduliExpanded[i].ConvertToInt());
		precomputedDCRTMultFloatTable[i] =
				((modulusQS.DividedBy(qi)).ModInverse(qi)*modulusS*modulusP).Mod(qi).ConvertToDouble()/qi.ConvertToDouble();
		//std::cout << precomputedDCRTDecryptionTable[i] << std::endl;
	}

	cryptoParamsFV->SetDCRTPolyMultFloatTable(precomputedDCRTMultFloatTable);

	std::cout << "generated the MultFloat table" << std::endl;

	std::vector<std::vector<native_int::BigInteger>> multInt(size+sizeS);
	for( usint newvIndex = 0 ; newvIndex < sizeS; newvIndex++ ) {
		BigInteger si = BigInteger(moduliS[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < size+sizeS; vIndex++ ) {
			BigInteger qi = BigInteger(moduliExpanded[vIndex].ConvertToInt());
			BigInteger num = modulusP*modulusS*((modulusQS.DividedBy(qi)).ModInverse(qi));
			BigInteger divBy = num / qi;
			multInt[vIndex].push_back(divBy.Mod(si).ConvertToInt());
		}
	}

	cryptoParamsFV->SetDCRTPolyMultIntTable(multInt);

	std::cout << "generated the MultInt table" << std::endl;

	std::vector<native_int::BigInteger> sInv(sizeS);
	for( usint vi = 0 ; vi < sizeS; vi++ ) {
		BigInteger si = BigInteger(moduliS[vi].ConvertToInt());
		BigInteger divBy = modulusS / si;
		sInv[vi] = divBy.ModInverse(si).Mod(si).ConvertToInt();
	}

	cryptoParamsFV->SetDCRTPolySInverseTable(sInv);

	std::cout << "generated the inverse table" << std::endl;

	std::vector<std::vector<native_int::BigInteger>> sDivsiModqi(size);
	for( usint newvIndex = 0 ; newvIndex < size; newvIndex++ ) {
		BigInteger qi = BigInteger(moduli[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < sizeS; vIndex++ ) {
			BigInteger si = BigInteger(moduliS[vIndex].ConvertToInt());
			BigInteger divBy = modulusS / si;
			sDivsiModqi[newvIndex].push_back(divBy.Mod(qi).ConvertToInt());
		}
	}

	cryptoParamsFV->SetDCRTPolysDivsiModqiTable(sDivsiModqi);

	std::cout << "generated the sDivsiModqi table" << std::endl;

	std::vector<native_int::BigInteger> sModqi(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		sModqi[vi] = modulusS.Mod(qi).ConvertToInt();
	}

	cryptoParamsFV->SetDCRTPolysModqiTable(sModqi);

	std::cout << "generated the sModqi table" << std::endl;


	return true;

}

template <>
shared_ptr<Ciphertext<DCRTPoly>> LPAlgorithmFV<DCRTPoly>::Encrypt(const shared_ptr<LPPublicKey<DCRTPoly>> publicKey,
		Poly &ptxt, bool doEncryption) const
{
	shared_ptr<Ciphertext<DCRTPoly>> ciphertext( new Ciphertext<DCRTPoly>(publicKey) );

	const shared_ptr<LPCryptoParametersFV<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersFV<DCRTPoly>>(publicKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	DCRTPoly plaintext(ptxt, elementParams);
	plaintext.SwitchFormat();

	if (doEncryption) {

		const std::vector<native_int::BigInteger> &deltaTable = cryptoParams->GetDCRTPolyDeltaTable();

		const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
		typename DCRTPoly::TugType tug;

		const DCRTPoly &p0 = publicKey->GetPublicElements().at(0);
		const DCRTPoly &p1 = publicKey->GetPublicElements().at(1);

		DCRTPoly u;

		//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
		if (cryptoParams->GetMode() == RLWE)
			u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
		else
			u = DCRTPoly(tug, elementParams, Format::EVALUATION);

		DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
		DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

		DCRTPoly c0(elementParams);
		DCRTPoly c1(elementParams);

		c0 = p0*u + e1 + plaintext.Times(deltaTable);

		c1 = p1*u + e2;

		ciphertext->SetElements({ c0, c1 });
		ciphertext->SetIsEncrypted(true);

	}
	else
	{

		DCRTPoly c0(plaintext);
		DCRTPoly c1(elementParams, Format::EVALUATION, true);

		ciphertext->SetElements({ c0, c1 });
		ciphertext->SetIsEncrypted(false);

	}

	return ciphertext;
}

template <>
DecryptResult LPAlgorithmFV<DCRTPoly>::Decrypt(const shared_ptr<LPPrivateKey<DCRTPoly>> privateKey,
		const shared_ptr<Ciphertext<DCRTPoly>> ciphertext,
		Poly *plaintext) const
{
	const shared_ptr<LPCryptoParametersFV<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersFV<DCRTPoly>>(privateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	const std::vector<DCRTPoly> &c = ciphertext->GetElements();

	const DCRTPoly &s = privateKey->GetPrivateElement();
	DCRTPoly sPower = s;

	DCRTPoly b = c[0];
	if(b.GetFormat() == Format::COEFFICIENT)
		b.SwitchFormat();

	DCRTPoly cTemp;
	for(size_t i=1; i<=ciphertext->GetDepth(); i++){
		cTemp = c[i];
		if(cTemp.GetFormat() == Format::COEFFICIENT)
			cTemp.SwitchFormat();

		b += sPower*cTemp;
		sPower *= s;
	}

	// Converts back to coefficient representation
	b.SwitchFormat();

	// Converts plaintext modulus to a 64-bit number
	const native_int::BigInteger &p = cryptoParams->GetPlaintextModulus().ConvertToInt();

	const std::vector<double> &lyamTable = cryptoParams->GetDCRTPolyDecryptionTable();
	const std::vector<native_int::BigInteger> &invTable = cryptoParams->GetDCRTPolyDecryptionIntTable();

	// this is the resulting vector of coefficients;
	// currently it is required to be a Poly of BigIntegers to be compatible with other API calls in the ryptocontext framework

	*plaintext = Poly(b.ScaleAndRound(p,invTable,lyamTable),COEFFICIENT);

	return DecryptResult(plaintext->GetLength());

}


template class LPCryptoParametersFV<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeFV<DCRTPoly>;
template class LPAlgorithmFV<DCRTPoly>;
template class LPAlgorithmParamsGenFV<DCRTPoly>;

}
