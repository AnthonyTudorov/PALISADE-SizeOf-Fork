#include "abe/kp_abe.h"
#include "abe/cp_abe.h"
#include "abe/ibe.h"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;

int KPABE_NANDGateTest(usint iter, int32_t base);
int KPABE_ANDGateTest(usint iter);
int KPABE_BenchmarkCircuitTest(usint iter, int32_t base);
int KPABE_APolicyCircuitTest(usint iter);
void CheckSecretKeyKP(usint m, RingMat &a, RingMat &evalBf, RingMat &sk, Poly &pubElemBeta);
usint EvalNANDTree(usint *x, usint ell);
int IBE_Test(int iter, int32_t base);
int TestKeyGenCP(const shared_ptr<ILParams> ilParams, usint m, usint ell, const usint s[], const RingMat &a, const RingMat &pubElemBPos, const RingMat &pubElemBNeg, const Poly &pubElemU, RingMat &sk);
int CPABE_Test(usint iter);


int main()
{

	std::cout << "-------Start demo for KP-ABE-------" << std::endl;
	KPABE_BenchmarkCircuitTest(1,8);
	std::cout << "-------End demo for KP-ABE-------" << std::endl << std::endl;

	std::cout << "-------Start demo for CP-ABE-------" << std::endl;
	CPABE_Test(1);
	std::cout << "-------End demo for CP-ABE-------" << std::endl << std::endl;

	std::cout << "-------Start demo for IBE-------" << std::endl;
	IBE_Test(1,16);
	std::cout << "-------End demo for IBE-------" << std::endl << std::endl;

	return 0;
}


int KPABE_BenchmarkCircuitTest(usint iter, int32_t base)
{
	usint ringDimension = 2048;   // ring dimension
	usint n = ringDimension*2;   // cyclotomic order
	usint k = 51;
	usint ell = 8; // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

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
	std::pair<RingMat, RLWETrapdoorPair<Poly>> trapdoorA = RLWETrapdoorUtility::TrapdoorGen(ilParams, SIGMA, base, true); // A.first is the public element

	Poly pubElemBeta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat ctCin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell+1];

	usint found  = 0;
	while(found == 0) {
		for(usint i=1; i<ell+1; i++)
			x[i] = rand()&0x1;
		if(EvalNANDTree(&x[1], ell) == 0)
			found = 1;
	}

	usint y;

	// plaintext
	Poly ptext(ilParams, COEFFICIENT, true);

	// circuit outputs
	RingMat evalBf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);  //evaluated Bs
	RingMat evalCf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);  // evaluated Cs
	RingMat ctCA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m); // CA

	// secret key corresponding to the circuit output
	RingMat sk(zero_alloc, 2, m);

	// decrypted text
	Poly dtext(ilParams, EVALUATION, true);

	int failure = 0;
	double start, finish, avg_keygen, avg_eval, avg_enc, avg_dec;
	avg_keygen=avg_eval=avg_enc=avg_dec=0.0;
	for(usint i=0; i<iter; i++)
	{
		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();
		start = currentDateTime();
		sender.Encrypt(ilParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1); // Cin and c1 are the ciphertext
		finish = currentDateTime();
		avg_enc += (finish - start);

		ctCA  = ctCin.ExtractRow(0);  // CA is A^T * s + e 0,A

		start = currentDateTime();
		receiver.EvalCT(ilParams, publicElementB, x, ctCin.ExtractRows(1, ell+1), &y, &evalCf);

		finish = currentDateTime();
		avg_eval += (finish - start);

		start = currentDateTime();
		pkg.EvalPK(ilParams, publicElementB, &evalBf);
		pkg.KeyGen(ilParams, trapdoorA.first, evalBf, pubElemBeta, trapdoorA.second, dgg, &sk);
		finish = currentDateTime();
		avg_keygen += (finish - start);
		CheckSecretKeyKP(m, trapdoorA.first, evalBf, sk, pubElemBeta);

		start = currentDateTime();
		receiver.Decrypt(ilParams, sk, ctCA, evalCf, c1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}

	}
	if(failure == 0) {
		std::cout << "Encryption/Decryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
		std::cout << "Average evaluation time : " << "\t" << (avg_eval)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	delete[] x;
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

	return 0;
}

/*
 * The access policy is x1*x2+x3*x4 = (1-x1x2)*(1-x3x4)
 */
int KPABE_APolicyCircuitTest(usint iter)
{
	usint ringDimension = 2048;   // ring dimension
	usint n = ringDimension*2;   // cyclotomic order
	usint k = 42;
	usint ell = 4; // No of attributes for NAND gate
	int32_t base = 2;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo)+1; /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

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
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGen(ilParams, SIGMA, base, true);

	Poly pubElemBeta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat ctCin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell+1];
	for(usint i=0; i<ell+1; i++)
		x[i] = 1;

	// plaintext
	Poly ptext(ilParams, COEFFICIENT, true);

	// outputs of the input gates
	RingMat tB(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat tC(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat wB(Poly::MakeAllocator(ilParams, EVALUATION), 2, m);
	RingMat wC(Poly::MakeAllocator(ilParams, EVALUATION), 2, m);
	usint wx[2];

	// circuit outputs
	RingMat evalBf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat evalCf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat ctCA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	usint y;  // output of the circuit; for the policy (i.e., x1=x2=1 OR x3=x4=1) it should be 0

	// secret key corresponding to the circuit output
	RingMat sKey(zero_alloc, 2, m);

	// decrypted text
	Poly dtext(ilParams, EVALUATION, true);

	int failure = 0;
	for(usint i=0; i<iter; i++)
	{
		std::cout << "Iter no. " << i << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();
		sender.Encrypt(ilParams, A.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

		ctCA  = ctCin.ExtractRow(0);
		auto pubElemB0 = publicElementB.ExtractRow(0);
		auto ctC0 = ctCin.ExtractRow(1);

		receiver.NANDGateEval(ilParams, pubElemB0, ctC0, &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &wx[0], &tB, &tC);

		for(usint i=0; i<m; i++) {
			wB(0, i) = tB(0, i);
			wC(0, i) = tC(0, i);
		}

		receiver.NANDGateEval(ilParams, pubElemB0, ctC0, &x[3], publicElementB.ExtractRows(3,4), ctCin.ExtractRows(4,5), &wx[1], &tB, &tC);

		for(usint i=0; i<m; i++) {
			wB(1, i) = tB(0, i);
			wC(1, i) = tC(0, i);
		}

		receiver.ANDGateEval(ilParams, wx, wB, wC, &y, &evalBf, &evalCf);

		pkg.KeyGen(ilParams, A.first, evalBf, pubElemBeta, A.second, dgg, &sKey);

		receiver.Decrypt(ilParams, sKey, ctCA, evalCf, c1, &dtext);

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}

	}
	if(failure == 0)
		std::cout << "Encryption is successful after " << iter << " iterations!\n";

	delete[] x;

	return 0;
}

int KPABE_NANDGateTest(usint iter, int32_t base)
{
	usint ringDimension = 1024;
	usint n = ringDimension*2;
	usint k = 36;
	usint ell = 2; // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length in base " << base << ": " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

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
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGen(ilParams, SIGMA, base, true);


	Poly pubElemBeta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat ctCin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell];
	x[0] = x[1] = x[2] = 1;
	usint y;
	//x[1] = 0;   // This should fail the NAND gate evaluation as now the output is 1 (should be 0 for a policy circuit)

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

	int failure = 0;
	double start, finish, avg_keygen, avg_eval, avg_enc, avg_dec;
	avg_keygen=avg_eval=avg_enc=avg_dec=0.0;
	for(usint i=0; i<iter; i++)
	{
		std::cout << "Iter no. " << i << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();
		start = currentDateTime();
		sender.Encrypt(ilParams, A.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);
		finish = currentDateTime();
		avg_enc += (finish - start);

		ctCA = ctCin.ExtractRow(0);

		start = currentDateTime();
		receiver.KPABE::NANDGateEval(ilParams,
				publicElementB.ExtractRow(0), ctCin.ExtractRow(1),
				&x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &pubElemBf, &ctCf);
		finish = currentDateTime();
		avg_eval += (finish - start);

		start = currentDateTime();
		pkg.KeyGen(ilParams, A.first, pubElemBf, pubElemBeta, A.second, dgg, &sk);
		finish = currentDateTime();
		avg_keygen += (finish - start);

		start = currentDateTime();
		receiver.Decrypt(ilParams, sk, ctCA, ctCf, c1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}
	}
	if(failure == 0) {
		std::cout << "Encryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
		std::cout << "Average evaluation time : " << "\t" << (avg_eval)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	return 0;
}

int KPABE_ANDGateTest(usint iter)
{
	usint ringDimension = 1024;
	usint n = ringDimension*2;
	usint k = 30;
	usint ell = 2; // No of attributes for NAND gate
	int32_t base = 2;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

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
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGen(ilParams, SIGMA, base, true);

	Poly pubElemBeta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat ctCin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell];
	x[0] = x[1] = x[2] = 0;
	usint y;
	//x[1] = x[2] = 1;   // When uncommented this should fail (a policy circuit always outputs 0

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

	int failure = 0;
	for(usint i=0; i<iter; i++)
	{
		std::cout << "Iter no. " << i << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();
		sender.Encrypt(ilParams, A.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

		ctCA = ctCin.ExtractRow(0);

		receiver.ANDGateEval(ilParams, &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &pubElemBf, &ctCf);

		pkg.KeyGen(ilParams, A.first, pubElemBf, pubElemBeta, A.second, dgg, &sk);

		receiver.Decrypt(ilParams, sk, ctCA, ctCf, c1, &dtext);

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}

	}
	if(failure == 0)
		std::cout << "Encryption is successful after " << iter << " iterations!\n";

	return 0;
}

void CheckSecretKeyKP(usint m, RingMat &a, RingMat &evalBf, RingMat &sk, Poly &pubElemBeta)
{
	Poly t(pubElemBeta);
	t.SetValuesToZero();
	for (usint i=0; i<m; i++) {
		t += (a(0, i)*sk(0, i));
		t += (evalBf(0, i)*sk(1, i));
	}

	if(t == pubElemBeta)
		std::cout << "Secret Key Generation is Successful!\n";
	else
		std::cout << "Secret Key Generation Fails!\n";
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

int IBE_Test(int iter, int32_t base)
{
	usint ringDimension = 1024;
	usint n = ringDimension*2;
	usint k = 36;

	BigInteger q = BigInteger::ONE << (k-1);
	//lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length in base " << base << ": "<< k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// for timing
	double start, finish, avg_keygen, avg_enc, avg_dec;

	IBE pkg, sender, receiver;

	start = currentDateTime();
	auto pubElemA = pkg.Setup(ilParams, base, dug);
	finish = currentDateTime();
	std::cout << "Setup time : " << "\t" << (finish - start) << " ms" << std::endl;

	sender.Setup(ilParams, base);
	receiver.Setup(ilParams, base);

	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, m, 1);

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);
	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	// ciphertext first and second parts
	RingMat ctC0(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	Poly ctC1(dug, ilParams, EVALUATION);

	int failure = 0;
	avg_keygen = avg_enc = avg_dec = 0.0;

	for(int i=0; i<iter; i++)
	{
	//	std::cout << "Iter no. " << i << std::endl;

		Poly u(dug, ilParams, EVALUATION);

		start = currentDateTime();
		pkg.KeyGen(ilParams, pubElemA.first, u, pubElemA.second, dgg, &sk);
		finish = currentDateTime();
		avg_keygen += (finish - start);
		std::cout << "Key generation time : " << "\t" << (finish - start) << " ms" << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();


		start = currentDateTime();
		sender.Encrypt(ilParams, pubElemA.first, u, ptext, dgg, dug, bug, &ctC0, &ctC1);
		finish = currentDateTime();
		avg_enc += (finish - start);
		std::cout << "Encryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		start = currentDateTime();
		receiver.Decrypt(ilParams, sk, ctC0, ctC1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);
		std::cout << "Decryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}
	}
	if(failure == 0) {
		std::cout << "Encryption/Decryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

	return 0;
}

int CPABE_Test(usint iter)
{
	usint ringDimension = 1024;
	usint n = ringDimension*2;
	usint k = 34;
	int32_t base = 4;
	usint ell = 32;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length in base " << base << ": "<< k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	RingMat pubElemBPos(zero_alloc, ell, m);
	RingMat pubElemBNeg(zero_alloc, ell, m);
	Poly u(pubElemBPos(0,0));

	// for timing
	double start, finish, avg_keygen, avg_enc, avg_dec;

	CPABE pkg, sender, receiver;

	start = currentDateTime();
	auto trapdoor = pkg.Setup(ilParams, base, ell, dug, &u, &pubElemBPos, &pubElemBNeg);
	finish = currentDateTime();
	std::cout << "Setup time : " << "\t" << (finish - start) << " ms" << std::endl;

	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// User attributes (randomly generated binary values)
	usint s[ell];

	// Access structure
	int w[ell];

	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, m, ell+1);

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);
	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	Poly c1(dug, ilParams, EVALUATION);

	int failure = 0;
	avg_keygen = avg_enc = avg_dec = 0.0;
	for(usint i=0; i<iter; i++)
	{
//		std::cout << "Iter no. " << i << std::endl;

		for(usint j=0; j<ell; j++)
			s[j] = rand()%2;

		for(usint j=0; j<ell; j++)
			w[j] = s[j];

		for(usint j=0; j<ell; j++)
			if(w[j]==1) {
				w[j] = 0;
				break;
			}

		for(usint j=0; j<ell; j++)
			if(s[j]==0) {
				w[j] = -1;
				break;
			}

		usint lenW = 0;
		for(usint j=0; j<ell; j++)
			if(w[j] != 0)
				lenW++;

		start = currentDateTime();
		pkg.KeyGen(ilParams, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, trapdoor.second, dgg, &sk);
		finish = currentDateTime();
		avg_keygen += (finish - start);
		std::cout << "Key generation time : " << "\t" << (finish - start) << " ms" << std::endl;
		TestKeyGenCP(ilParams, m, ell, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, sk);


		RingMat ctW(Poly::MakeAllocator(ilParams, EVALUATION), lenW+1, m);
		RingMat ctCPos(Poly::MakeAllocator(ilParams, EVALUATION), ell-lenW, m);
		RingMat nC(Poly::MakeAllocator(ilParams, EVALUATION), ell-lenW, m);

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();

		start = currentDateTime();
		sender.Encrypt(ilParams, trapdoor.first, pubElemBPos, pubElemBNeg, u, w, ptext, dgg, dug, bug, &ctW, &ctCPos, &nC, &c1);
		finish = currentDateTime();
		avg_enc += (finish - start);
		std::cout << "Encryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		start = currentDateTime();
		receiver.Decrypt(ilParams, w, s, sk, ctW, ctCPos, nC, c1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);
		std::cout << "Decryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}
	}
	if(failure == 0) {
		std::cout << "Encryption/Decryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	delete[] w;
	delete[] s;

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

	return 0;
}

int TestKeyGenCP(
	const shared_ptr<ILParams> ilParams,
	const usint m,
	const usint ell,
	const usint s[],
	const RingMat &pubTA,
	const RingMat &publicElemBPos,
	const RingMat &publicElemBNeg,
	const Poly &u,
	RingMat &sk
)
{
	Poly t1(ilParams, EVALUATION, true);
	Poly t2(ilParams, EVALUATION, true);

	for(usint i=0; i<ell; i++) {
		if(s[i]==1) {
			t2 = publicElemBPos(i, 0)*sk(0, i+1);
			for(usint j=1; j<m; j++)
				t2 += publicElemBPos(i, j)*sk(j, i+1);
		}
		else {
			t2 = publicElemBNeg(i, 0)*sk(0, i+1);
			for(usint j=1; j<m; j++)
				t2 += publicElemBNeg(i, j)*sk(j, i+1);
		}
		t1 += t2;
	}

	t2 = pubTA(0, 0)*sk(0, 0);
	for(usint j=1; j<m; j++)
		t2 += pubTA(0, j)*sk(j, 0);

	t1 += t2;

	if (u == t1)
		std::cout << "Key generation is successful!\n";
	else
		std::cout << "Key generation fails!\n";
	return 0;
}



