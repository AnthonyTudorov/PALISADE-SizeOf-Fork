#include "abe/kp_abe.h"
#include "abe/kp_abe.cpp"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;

	void KPABEBenchMarkCircuit(int32_t base, usint k, usint ringDimension, usint iter);
template <class Element, class Element2>
	void TestDCRTVecDecompose(int32_t base, usint k, usint ringDimension);
	int KPABE_BenchmarkCircuitTestDCRT(usint iter, int32_t base);
	usint EvalNANDTree(usint *x, usint ell);
	void KPABE_NANDGATE(int32_t base, usint k, usint ringDimension);
	void KPABE_NANDGATEDCRT(int32_t base, usint k, usint ringDimension);
	void KPABEANDGate(int32_t base, usint k, usint ringDimension);
	void KPABEANDGateDCRT(int32_t base, usint k, usint ringDimension);

int main()
{


	KPABE_BenchmarkCircuitTestDCRT(4, 32);
	KPABEBenchMarkCircuit(2, 51, 2048, 100);
	KPABE_NANDGATE(32,51,2048);
	KPABE_NANDGATEDCRT(16, 8, 2048);
	KPABEANDGate(32,51,2048);
	KPABEANDGateDCRT(16, 8, 2048);

	TestDCRTVecDecompose<DCRTPoly, Poly>(16,51,32);

	return 0;
}

void KPABEBenchMarkCircuit(int32_t base, usint k, usint ringDimension, usint iter){
	usint n = ringDimension*2;   // cyclotomic order
	usint ell = 4; // No of attributes

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;

	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> trapdoorA = RLWETrapdoorUtility<Poly>::TrapdoorGen(ilParams, SIGMA, base, true); // A.first is the public element

	Poly pubElemBeta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat ctCin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE<Poly, Poly> pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	usint x[] = {1,1,1}; // array of attributes, everything is set to 1 for NAND gate evaluation, values set based on experimental results

	usint y;

	// plaintext
	Poly ptext(ilParams, COEFFICIENT, true);

	// circuit outputs
	RingMat evalBf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);  //evaluated Bs
	RingMat evalCf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);  // evaluated Cs
	RingMat ctCA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m); // CA


	for(usint i = 0; i < iter; i++){
	// secret key corresponding to the circuit output
	RingMat sk(zero_alloc, 2, m);

	// decrypted text
	Poly dtext(ilParams, EVALUATION, true);
// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
	ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
	ptext.SwitchFormat();
	sender.Encrypt(ilParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1); // Cin and c1 are the ciphertext

	ctCA  = ctCin.ExtractRow(0);  // CA is A^T * s + e 0,A

	receiver.EvalCT(ilParams, publicElementB, x, ctCin.ExtractRows(1, ell+1), &y, &evalCf);

	pkg.EvalPK(ilParams, publicElementB, &evalBf);
	pkg.KeyGen(ilParams, trapdoorA.first, evalBf, pubElemBeta, trapdoorA.second, dgg, &sk);

	Poly t(pubElemBeta);
	t.SetValuesToZero();

	for (usint i=0; i<m; i++) {
		t += (trapdoorA.first(0, i)*sk(0, i));
		t += (evalBf(0, i)*sk(1, i));
	}


	receiver.Decrypt(ilParams, sk, ctCA, evalCf, c1, &dtext);
	receiver.Decode(&dtext);

	ptext.SwitchFormat();

	if(ptext.GetValues() == dtext.GetValues()){
		std::cout << "Decrypted Properly" << std::endl;
	}

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

	}
}

int KPABE_BenchmarkCircuitTestDCRT(usint iter, int32_t base)

{
	usint ringDimension = 2048;   // ring dimension
	usint n = ringDimension * 2;   // cyclotomic order
//	usint k = 21;
	usint ell = 4; // No of attributes

//	native_int::BigInteger q = native_int::BigInteger::ONE << (k - 1);
//	q = lbcrypto::FirstPrime<native_int::BigInteger>(k, n);

	native_int::BigInteger q("2101249");

	native_int::BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val - 1.0) / log(base) + 1.0;
	size_t k_ = (usint)floor(logTwo) + 1; //  (+1) is For NAF
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;


//	native_int::BigInteger nextQ = native_int::BigInteger::ONE << (k-1);
//	nextQ = lbcrypto::NextPrime<native_int::BigInteger>(q, n);
//	std::cout << "nextQ: " << nextQ << std::endl;

	native_int::BigInteger nextQ("2236417");

	native_int::BigInteger nextRootOfUnity(RootOfUnity<native_int::BigInteger>(n, nextQ));


//	native_int::BigInteger nextQ2 = native_int::BigInteger::ONE << (k-1);
//	nextQ2 = lbcrypto::NextPrime<native_int::BigInteger>(nextQ, n);

	native_int::BigInteger nextQ2("2277377");
	native_int::BigInteger nextRootOfUnity2(RootOfUnity<native_int::BigInteger>(n, nextQ2));

	usint m = 3 *  k_ + 2;

	std::vector<native_int::BigInteger> moduli;
	std::vector<native_int::BigInteger> roots_Of_Unity;
	moduli.reserve(3);
	roots_Of_Unity.reserve(3);

	moduli.push_back(q);
	moduli.push_back(nextQ);
	moduli.push_back(nextQ2);

	roots_Of_Unity.push_back(rootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity2);

	BigInteger bigModulus = BigInteger("2101249") * BigInteger("2236417") * BigInteger("2277377");

	BigInteger bigRootOfUnity(RootOfUnity(n,bigModulus));

	BinaryUniformGenerator bug = BinaryUniformGenerator();


	shared_ptr<ILDCRTParams<BigInteger>> ilDCRTParams(new ILDCRTParams<BigInteger>(n, moduli, roots_Of_Unity));

	shared_ptr<ILParams> ilParamsConsolidated(new ILParams(n, bigModulus, bigRootOfUnity));
//	shared_ptr<ILParams> ilParamsConsolidated(new ILParams(n, bigModulus, rootOfUnity));

	auto zero_alloc = DCRTPoly::MakeAllocator(ilDCRTParams, COEFFICIENT);

	DCRTPoly::DggType dgg = DCRTPoly::DggType(SIGMA);
	DCRTPoly::DugType dug = DCRTPoly::DugType();

	// Precompuations for FTT
//	ChineseRemainderTransformFTT<native_int::BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// Trapdoor Generation
	std::pair<RingMatDCRT, RLWETrapdoorPair<DCRTPoly>> trapdoorA = RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(ilDCRTParams, SIGMA, base, true); // A.first is the public element

	DCRTPoly pubElemBeta(dug, ilDCRTParams, EVALUATION);

	RingMatDCRT publicElementB(zero_alloc, ell + 1, m);
	RingMatDCRT ctCin(zero_alloc, ell + 2, m);
	DCRTPoly c1(dug, ilDCRTParams, EVALUATION);

	KPABE<DCRTPoly, Poly> pkg, sender, receiver;

	pkg.Setup(ilDCRTParams, base, ell, dug, &publicElementB);
	sender.Setup(ilDCRTParams, base, ell);
	receiver.Setup(ilDCRTParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell + 1];

	usint found = 0;
	while (found == 0) {
		for (usint i = 1; i<ell + 1; i++)
			x[i] = rand() & 0x1;
		if (EvalNANDTree(&x[1], ell) == 0)
			found = 1;
	}

	usint y;

	double avg_keygen, avg_eval, avg_enc, avg_dec;
		avg_keygen = avg_eval = avg_enc = avg_dec = 0.0;

	// plaintext
	for(usint i=0; i<iter; i++)
	{

		Poly ptext1(ilParamsConsolidated, COEFFICIENT, true);
		ptext1.SetValues(bug.GenerateVector(ringDimension, bigModulus), COEFFICIENT);

		DCRTPoly ptext(ptext1, ilDCRTParams);

		// circuit outputs
		RingMatDCRT evalBf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  //evaluated Bs
		RingMatDCRT evalCf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  // evaluated Cs
		RingMatDCRT ctCA(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m); // CA

																	   // secret key corresponding to the circuit output
		RingMatDCRT sk(zero_alloc, 2, m);

		// decrypted text
		DCRTPoly dtext(ilDCRTParams, EVALUATION, true);

		double start, finish;

		ptext.SwitchFormat();
		start = currentDateTime();
		sender.Encrypt(ilDCRTParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1); // Cin and c1 are the ciphertext
		finish = currentDateTime();
		avg_enc += (finish - start);

		ctCA = ctCin.ExtractRow(0);  // CA is A^T * s + e 0,A

		start = currentDateTime();
		receiver.EvalCTDCRT(ilDCRTParams, publicElementB, x, ctCin.ExtractRows(1, ell + 1), &y, &evalCf, ilParamsConsolidated);

		finish = currentDateTime();
		avg_eval += (finish - start);

		start = currentDateTime();
		pkg.EvalPKDCRT(ilDCRTParams, publicElementB, &evalBf, ilParamsConsolidated);
		pkg.KeyGen(ilDCRTParams, trapdoorA.first, evalBf, pubElemBeta, trapdoorA.second, dgg, &sk);
		finish = currentDateTime();
		avg_keygen += (finish - start);
	//	CheckSecretKeyKPDCRT(m, trapdoorA.first, evalBf, sk, pubElemBeta);

		start = currentDateTime();
		receiver.Decrypt(ilDCRTParams, sk, ctCA, evalCf, c1, &dtext);

		Poly dtextPoly(dtext.CRTInterpolate());

		receiver.Decode(&dtextPoly);

		finish = currentDateTime();
		avg_dec += (finish - start);

		if(ptext1.GetValues() != dtextPoly.GetValues()){
			std::cout << "Decryption fails at iteration: " << i << std::endl;
			return 0;
		}
	}

		std::cout << "Encryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
		std::cout << "Average evaluation time : " << "\t" << (avg_eval)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;


	delete[] x;
//	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

	return 0;
}

template <class Element, class Element2>
void TestDCRTVecDecompose(int32_t base, usint k, usint ringDimension){

	usint n = ringDimension*2;   // cyclotomic order

	native_int::BigInteger q = native_int::BigInteger(1) << (k-1);
	q = lbcrypto::FirstPrime<native_int::BigInteger>(k,n);
	native_int::BigInteger rootOfUnity(RootOfUnity<native_int::BigInteger>(n, q));

	native_int::BigInteger nextQ = native_int::BigInteger(1) << (k-1);
	nextQ = lbcrypto::NextPrime<native_int::BigInteger>(q, n);
	native_int::BigInteger nextRootOfUnity(RootOfUnity<native_int::BigInteger>(n, nextQ));

	usint m = k + k +2;

	std::vector<native_int::BigInteger> moduli;
	std::vector<native_int::BigInteger> roots_Of_Unity;
	moduli.reserve(2);
	roots_Of_Unity.reserve(2);

	moduli.push_back(q);
	moduli.push_back(nextQ);

	roots_Of_Unity.push_back(rootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity);

	BigInteger bigModulus("1");
	long double qDouble = q.ConvertToDouble();
	long double nextQdouble = nextQ.ConvertToDouble();

	bigModulus = BigInteger(qDouble)* BigInteger(nextQdouble);

	BigInteger bigRootOfUnity(RootOfUnity(n,bigModulus));

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(n, moduli, roots_Of_Unity));
	shared_ptr<ILParams> ilParams(new ILParams(n, bigModulus, bigRootOfUnity));

	auto zero_alloc_poly = Element2::MakeAllocator(ilParams, COEFFICIENT);
	auto zero_alloc = Element::MakeAllocator(params, COEFFICIENT);
	auto zero_alloc_eval = DCRTPoly::MakeAllocator(params, EVALUATION);

	RingMatDCRT matrixTobeDecomposed(zero_alloc, 1, m);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	DCRTPoly::DugType dug = DCRTPoly::DugType();

	for (usint i = 0; i < matrixTobeDecomposed.GetRows(); i++){
		for (usint j = 0; j < matrixTobeDecomposed.GetCols(); j++) {
				matrixTobeDecomposed(i,j) = Element(dug, params, COEFFICIENT);
				matrixTobeDecomposed(i, j).SwitchFormat(); // always kept in EVALUATION format
			}
	}

	RingMatDCRT results(zero_alloc_eval,1,m);
	RingMatDCRT g = RingMatDCRT(zero_alloc_eval, 1, m).GadgetVector(base);

	RingMatDCRT psiDCRT(zero_alloc, m, m);
	RingMat psi(zero_alloc_poly, m, m);

	RingMat matrixDecomposePoly(zero_alloc_poly, 1, m);

	for(usint i = 0; i < m; i++){
		matrixDecomposePoly(0,i) = matrixTobeDecomposed(0,i).CRTInterpolate();
	}

	lbcrypto::PolyVec2BalDecom(ilParams, base, k+k, matrixDecomposePoly, &psi);

	for(usint i = 0; i < psi.GetRows(); i++){
				for(usint j = 0; j < psi.GetCols();j++){
					Element temp(psi(i,j), params);
					psiDCRT(i,j) = temp;
				}
			}
	psiDCRT.SwitchFormat();
	results = g * psiDCRT;

	for(usint i = 0; i < results.GetRows(); i++){
		for(usint j =0; j < results.GetCols(); j++){
			results(i,j).PrintValues();
			matrixTobeDecomposed(i,j).PrintValues();
		}
	}

}

usint EvalNANDTree(usint *x, usint ell)
{
	usint y;

	if(ell == 2) {
		y = 1 - x[0]*x[1];
		return y;
	}
	else {
		ell >>= 1;
		y = 1 - (EvalNANDTree(&x[0], ell)*EvalNANDTree(&x[ell], ell));
	}
	return y;
}

void KPABE_NANDGATE(int32_t base, usint k, usint ringDimension){
			usint n = ringDimension*2;
			usint ell = 2; // No of attributes for NAND gate

			BigInteger q = BigInteger::ONE << (k-1);
			q = lbcrypto::FirstPrime<BigInteger>(k,n);
			BigInteger rootOfUnity(RootOfUnity(n, q));

			double val = q.ConvertToDouble();
			double logTwo = log(val-1.0)/log(base)+1.0;
			size_t k_ = (usint) floor(logTwo) + 1;

			usint m = k_+2;

			shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

			auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

			DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
			Poly::DugType dug = Poly::DugType();
			dug.SetModulus(q);
			BinaryUniformGenerator bug = BinaryUniformGenerator();

			// Precompuations for FTT
			ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

			// Trapdoor Generation
			std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility<Poly>::TrapdoorGen(ilParams, SIGMA, base, true);

			Poly pubElemBeta(dug, ilParams, EVALUATION);

			RingMat publicElementB(zero_alloc, ell+1, m);
			RingMat ctCin(zero_alloc, ell+2, m);
			Poly c1(dug, ilParams, EVALUATION);

			KPABE<Poly, Poly> pkg, sender, receiver;

			pkg.Setup(ilParams, base, ell, dug, &publicElementB);
			sender.Setup(ilParams, base, ell);
			receiver.Setup(ilParams, base, ell);

			// Attribute values all are set to 1 for NAND gate evaluation
			usint *x = new usint[ell+1];
			x[0] = x[1] = x[2] = 1;
			usint y;

			// plain text in $R_2$
			Poly ptext(ilParams, COEFFICIENT, true);

			// circuit outputs
			RingMat pubElemBf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
			RingMat ctCf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
			RingMat ctCA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);

			// Secret key for the output of the circuit
			RingMat sk(zero_alloc, 2, m);

			// text after the decryption
			Poly dtext(ilParams, EVALUATION, true);

			// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
			ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
			ptext.SwitchFormat();

			sender.Encrypt(ilParams, A.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

			ctCA = ctCin.ExtractRow(0);

			receiver.KPABE::NANDGateEvalPK(ilParams, publicElementB.ExtractRow(0), publicElementB.ExtractRows(1,2), &pubElemBf);

			receiver.KPABE::NANDGateEvalCT(ilParams, ctCin.ExtractRow(1), &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &ctCf);

			pkg.KeyGen(ilParams, A.first, pubElemBf, pubElemBeta, A.second, dgg, &sk);

			receiver.Decrypt(ilParams, sk, ctCA, ctCf, c1, &dtext);
			receiver.Decode(&dtext);

			ptext.SwitchFormat();
			if(ptext.GetValues() ==  dtext.GetValues()){
				std::cout << "Success" << std::endl;
			}
			delete[] x;
}

void KPABE_NANDGATEDCRT(int32_t base, usint k, usint ringDimension){
		usint n = ringDimension * 2;   // cyclotomic order
	//	usint k = 21;
		usint ell = 4; // No of attributes

	//	native_int::BigInteger q = native_int::BigInteger::ONE << (k - 1);
	//	q = lbcrypto::FirstPrime<native_int::BigInteger>(k, n);

		native_int::BigInteger q("2101249");

		native_int::BigInteger rootOfUnity(RootOfUnity(n, q));

	//	native_int::BigInteger rootOfUnity("794438271477401");

		double val = q.ConvertToDouble();
		double logTwo = log(val - 1.0) / log(base) + 1.0;
		size_t k_ = (usint)floor(logTwo) + 1; //  (+1) is For NAF
		std::cout << "q: " << q << std::endl;
		std::cout << "modulus length: " << k_ << std::endl;
		std::cout << "root of unity: " << rootOfUnity << std::endl;
		std::cout << "Standard deviation: " << SIGMA << std::endl;


	//	native_int::BigInteger nextQ = native_int::BigInteger::ONE << (k-1);
	//	nextQ = lbcrypto::NextPrime<native_int::BigInteger>(q, n);
	//	std::cout << "nextQ: " << nextQ << std::endl;

		native_int::BigInteger nextQ("2236417");

		native_int::BigInteger nextRootOfUnity(RootOfUnity<native_int::BigInteger>(n, nextQ));


	//	native_int::BigInteger nextQ2 = native_int::BigInteger::ONE << (k-1);
	//	nextQ2 = lbcrypto::NextPrime<native_int::BigInteger>(nextQ, n);

		native_int::BigInteger nextQ2("2277377");
		native_int::BigInteger nextRootOfUnity2(RootOfUnity<native_int::BigInteger>(n, nextQ2));

		usint m = 3 *  k_ + 2;

		std::vector<native_int::BigInteger> moduli;
		std::vector<native_int::BigInteger> roots_Of_Unity;
		moduli.reserve(3);
		roots_Of_Unity.reserve(3);

		moduli.push_back(q);
		moduli.push_back(nextQ);
		moduli.push_back(nextQ2);

		roots_Of_Unity.push_back(rootOfUnity);
		roots_Of_Unity.push_back(nextRootOfUnity);
		roots_Of_Unity.push_back(nextRootOfUnity2);


		BigInteger bigModulus = BigInteger("2101249") * BigInteger("2236417") * BigInteger("2277377");

		BigInteger bigRootOfUnity(RootOfUnity(n,bigModulus));

		BinaryUniformGenerator bug = BinaryUniformGenerator();


		shared_ptr<ILDCRTParams<BigInteger>> ilDCRTParams(new ILDCRTParams<BigInteger>(n, moduli, roots_Of_Unity));

		shared_ptr<ILParams> ilParamsConsolidated(new ILParams(n, bigModulus, bigRootOfUnity));

		auto zero_alloc = DCRTPoly::MakeAllocator(ilDCRTParams, COEFFICIENT);

		DCRTPoly::DggType dgg = DCRTPoly::DggType(SIGMA);
		DCRTPoly::DugType dug = DCRTPoly::DugType();

		// Trapdoor Generation
		std::pair<RingMatDCRT, RLWETrapdoorPair<DCRTPoly>> trapdoorA = RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(ilDCRTParams, SIGMA, base, true); // A.first is the public element

		DCRTPoly pubElemBeta(dug, ilDCRTParams, EVALUATION);

		RingMatDCRT publicElementB(zero_alloc, ell + 1, m);
		RingMatDCRT ctCin(zero_alloc, ell + 2, m);
		DCRTPoly c1(dug, ilDCRTParams, EVALUATION);

		KPABE<DCRTPoly, Poly> pkg, sender, receiver;

		pkg.Setup(ilDCRTParams, base, ell, dug, &publicElementB);
		sender.Setup(ilDCRTParams, base, ell);
		receiver.Setup(ilDCRTParams, base, ell);

		// Attribute values all are set to 1 for NAND gate evaluation
		usint *x = new usint[ell+1];
		x[0] = x[1] = x[2] = 1;
		usint y;

		Poly ptext1(ilParamsConsolidated, COEFFICIENT, true);
		ptext1.SetValues(bug.GenerateVector(ringDimension, bigModulus), COEFFICIENT);

		DCRTPoly ptext(ptext1, ilDCRTParams);

		// circuit outputs
		RingMatDCRT pubElemBf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  //evaluated Bs
		RingMatDCRT ctCf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  // evaluated Cs
		RingMatDCRT ctCA(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m); // CA

																	   // secret key corresponding to the circuit output
		RingMatDCRT sk(zero_alloc, 2, m);

		// decrypted text
		DCRTPoly dtext(ilDCRTParams, EVALUATION, true);

		ptext.SwitchFormat();

		sender.Encrypt(ilDCRTParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

		ctCA = ctCin.ExtractRow(0);

		receiver.NANDGateEvalPKDCRT(ilDCRTParams, publicElementB.ExtractRow(0), publicElementB.ExtractRows(1,2), &pubElemBf, ilParamsConsolidated);

		receiver.NANDGateEvalCTDCRT(ilDCRTParams, ctCin.ExtractRow(1), &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &ctCf, ilParamsConsolidated);

		pkg.KeyGen(ilDCRTParams, trapdoorA.first, pubElemBf, pubElemBeta,trapdoorA.second, dgg, &sk);

		receiver.Decrypt(ilDCRTParams, sk, ctCA, ctCf, c1, &dtext);

		Poly dtextPoly(dtext.CRTInterpolate());

		receiver.Decode(&dtextPoly);

		ptext.SwitchFormat();
		if(ptext1.GetValues() ==  dtextPoly.GetValues()){
			std::cout << "Success" << std::endl;
		}
		delete[] x;
}

void KPABEANDGate(int32_t base, usint k, usint ringDimension){

		usint n = ringDimension*2;
		usint ell = 4; // No of attributes for AND gate

		BigInteger q = BigInteger::ONE << (k-1);
		q = lbcrypto::FirstPrime<BigInteger>(k,n);
		BigInteger rootOfUnity(RootOfUnity(n, q));

		double val = q.ConvertToDouble();
		double logTwo = log(val-1.0)/log(base)+1.0;
		size_t k_ = (usint) floor(logTwo) + 1;
		usint m = k_+2;

		shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

		auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

		DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
		Poly::DugType dug = Poly::DugType();
		dug.SetModulus(q);
		BinaryUniformGenerator bug = BinaryUniformGenerator();

		// Precompuations for FTT
		ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

		// Trapdoor Generation
		std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility<Poly>::TrapdoorGen(ilParams, SIGMA, base, true);

		Poly pubElemBeta(dug, ilParams, EVALUATION);

		RingMat publicElementB(zero_alloc, ell+1, m);
		RingMat ctCin(zero_alloc, ell+2, m);
		Poly c1(dug, ilParams, EVALUATION);

		KPABE<Poly, Poly> pkg, sender, receiver;

		pkg.Setup(ilParams, base, ell, dug, &publicElementB);
		sender.Setup(ilParams, base, ell);
		receiver.Setup(ilParams, base, ell);

		// Attribute values all are set to 1 for NAND gate evaluation
		usint *x  = new usint[ell];
		x[0] = x[1] = x[2] = 0;
		usint y;

		// plain text in $R_2$
		Poly ptext(ilParams, COEFFICIENT, true);

		// circuit outputs
		RingMat pubElemBf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
		RingMat ctCf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
		RingMat ctCA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);

		// Secret key for the output of the circuit
		RingMat sk(zero_alloc, 2, m);

		// text after the decryption
		Poly dtext(ilParams, EVALUATION, true);

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();
		sender.Encrypt(ilParams, A.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

		ctCA = ctCin.ExtractRow(0);

		receiver.ANDGateEvalPK(ilParams, publicElementB.ExtractRows(1,2), &pubElemBf);
		receiver.ANDGateEvalCT(ilParams, &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &ctCf);

		pkg.KeyGen(ilParams, A.first, pubElemBf, pubElemBeta, A.second, dgg, &sk);

		receiver.Decrypt(ilParams, sk, ctCA, ctCf, c1, &dtext);
		receiver.Decode(&dtext);

		ptext.SwitchFormat();
		if(ptext.GetValues() ==  dtext.GetValues()){
			std::cout << "Success" << std::endl;
		}
		delete[] x;
}

void KPABEANDGateDCRT(int32_t base, usint k, usint ringDimension){

	usint n = ringDimension * 2;   // cyclotomic order
//	usint k = 21;
	usint ell = 4; // No of attributes

//	native_int::BigInteger q = native_int::BigInteger::ONE << (k - 1);
//	q = lbcrypto::FirstPrime<native_int::BigInteger>(k, n);

	native_int::BigInteger q("2101249");

	native_int::BigInteger rootOfUnity(RootOfUnity(n, q));

//	native_int::BigInteger rootOfUnity("794438271477401");

	double val = q.ConvertToDouble();
	double logTwo = log(val - 1.0) / log(base) + 1.0;
	size_t k_ = (usint)floor(logTwo) + 1; //  (+1) is For NAF
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;


//	native_int::BigInteger nextQ = native_int::BigInteger::ONE << (k-1);
//	nextQ = lbcrypto::NextPrime<native_int::BigInteger>(q, n);
//	std::cout << "nextQ: " << nextQ << std::endl;

	native_int::BigInteger nextQ("2236417");

	native_int::BigInteger nextRootOfUnity(RootOfUnity<native_int::BigInteger>(n, nextQ));


//	native_int::BigInteger nextQ2 = native_int::BigInteger::ONE << (k-1);
//	nextQ2 = lbcrypto::NextPrime<native_int::BigInteger>(nextQ, n);

	native_int::BigInteger nextQ2("2277377");
	native_int::BigInteger nextRootOfUnity2(RootOfUnity<native_int::BigInteger>(n, nextQ2));

	usint m = 3 *  k_ + 2;

	std::vector<native_int::BigInteger> moduli;
	std::vector<native_int::BigInteger> roots_Of_Unity;
	moduli.reserve(3);
	roots_Of_Unity.reserve(3);

	moduli.push_back(q);
	moduli.push_back(nextQ);
	moduli.push_back(nextQ2);

	roots_Of_Unity.push_back(rootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity2);


	BigInteger bigModulus = BigInteger("2101249") * BigInteger("2236417") * BigInteger("2277377");

	BigInteger bigRootOfUnity(RootOfUnity(n,bigModulus));

	BinaryUniformGenerator bug = BinaryUniformGenerator();


	shared_ptr<ILDCRTParams<BigInteger>> ilDCRTParams(new ILDCRTParams<BigInteger>(n, moduli, roots_Of_Unity));

	shared_ptr<ILParams> ilParamsConsolidated(new ILParams(n, bigModulus, bigRootOfUnity));

	auto zero_alloc = DCRTPoly::MakeAllocator(ilDCRTParams, COEFFICIENT);

	DCRTPoly::DggType dgg = DCRTPoly::DggType(SIGMA);
	DCRTPoly::DugType dug = DCRTPoly::DugType();

	// Trapdoor Generation
	std::pair<RingMatDCRT, RLWETrapdoorPair<DCRTPoly>> trapdoorA = RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(ilDCRTParams, SIGMA, base, true); // A.first is the public element

	DCRTPoly pubElemBeta(dug, ilDCRTParams, EVALUATION);

	RingMatDCRT publicElementB(zero_alloc, ell + 1, m);
	RingMatDCRT ctCin(zero_alloc, ell + 2, m);
	DCRTPoly c1(dug, ilDCRTParams, EVALUATION);

	KPABE<DCRTPoly, Poly> pkg, sender, receiver;

	pkg.Setup(ilDCRTParams, base, ell, dug, &publicElementB);
	sender.Setup(ilDCRTParams, base, ell);
	receiver.Setup(ilDCRTParams, base, ell);


	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x  = new usint[ell];
	x[0] = x[1] = x[2] = 0;
	usint y;

	Poly ptext1(ilParamsConsolidated, COEFFICIENT, true);
	ptext1.SetValues(bug.GenerateVector(ringDimension, bigModulus), COEFFICIENT);

	DCRTPoly ptext(ptext1, ilDCRTParams);

	// circuit outputs
	RingMatDCRT pubElemBf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  //evaluated Bs
	RingMatDCRT ctCf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  // evaluated Cs
	RingMatDCRT ctCA(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m); // CA

																   // secret key corresponding to the circuit output
	RingMatDCRT sk(zero_alloc, 2, m);

	// decrypted text
	DCRTPoly dtext(ilDCRTParams, EVALUATION, true);

	ptext.SwitchFormat();

	sender.Encrypt(ilDCRTParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

	ctCA = ctCin.ExtractRow(0);

	receiver.ANDGateEvalPKDCRT(ilDCRTParams, publicElementB.ExtractRows(1,2), &pubElemBf, ilParamsConsolidated);
	receiver.ANDGateEvalCTDCRT(ilDCRTParams, &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &ctCf, ilParamsConsolidated);

	pkg.KeyGen(ilDCRTParams, trapdoorA.first, pubElemBf, pubElemBeta,trapdoorA.second, dgg, &sk);

	receiver.Decrypt(ilDCRTParams, sk, ctCA, ctCf, c1, &dtext);

	Poly dtextPoly(dtext.CRTInterpolate());

	receiver.Decode(&dtextPoly);

	ptext.SwitchFormat();
	if(ptext1.GetValues() ==  dtextPoly.GetValues()){
		std::cout << "Success" << std::endl;
	}
	delete[] x;

}




