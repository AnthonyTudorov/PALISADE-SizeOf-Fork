#include "abe/kp_abe_rns.h"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

#define PROFIILE

using namespace lbcrypto;

int KPABE_BenchmarkCircuitTestDCRT(usint iter, int32_t base);
usint EvalNANDTree(usint *x, usint ell);

int main()
{

	KPABE_BenchmarkCircuitTestDCRT(4, 16);

	return 0;
}

int KPABE_BenchmarkCircuitTestDCRT(usint iter, int32_t base)

{
	usint n = 64;   // cyclotomic order
	size_t kRes = 51;
	usint ell = 4; // No of attributes

	size_t size = 1;

	double sigma = SIGMA;

	std::vector<NativeInteger> moduli;
	std::vector<NativeInteger> roots_Of_Unity;

	NativeInteger q = NativeInteger(1) << (kRes-1);
	q = lbcrypto::FirstPrime<NativeInteger>(kRes,2*n);
	NativeInteger rootOfUnity(RootOfUnity<NativeInteger>(2*n, q));
	moduli.push_back(q);
	roots_Of_Unity.push_back(rootOfUnity);

	NativeInteger nextQ = q;
	for (size_t i = 1; i < size; i++) {
		nextQ = lbcrypto::NextPrime<NativeInteger>(nextQ, 2*n);
		NativeInteger nextRootOfUnity(RootOfUnity<NativeInteger>(2*n, nextQ));
		moduli.push_back(nextQ);
		roots_Of_Unity.push_back(nextRootOfUnity);
	}

	shared_ptr<ILDCRTParams<BigInteger>> ilDCRTParams(new ILDCRTParams<BigInteger>(2*n, moduli, roots_Of_Unity));

	size_t digitCount = (long)ceil(log2(ilDCRTParams->GetParams()[0]->GetModulus().ConvertToDouble())/log2(base));
	size_t k = digitCount*ilDCRTParams->GetParams().size();

	size_t m = k + 2;

	auto zero_alloc = DCRTPoly::Allocator(ilDCRTParams, COEFFICIENT);

	DCRTPoly::DggType dgg = DCRTPoly::DggType(SIGMA);
	DCRTPoly::DugType dug = DCRTPoly::DugType();
	DCRTPoly::BugType bug = DCRTPoly::BugType();

	// Trapdoor Generation
	std::pair<RingMatDCRT, RLWETrapdoorPair<DCRTPoly>> trapdoorA =
			RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(ilDCRTParams, SIGMA, base, true); // A.first is the public element

	DCRTPoly pubElemBeta(dug, ilDCRTParams, EVALUATION);

	RingMatDCRT publicElementB(zero_alloc, ell + 1, m);
	RingMatDCRT ctCin(zero_alloc, ell + 2, m);
	DCRTPoly c1(dug, ilDCRTParams, EVALUATION);

	KPABErns pkg, sender, receiver;

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

	TimeVar t1;
	double avg_keygen(0.0), avg_evalct(0.0), avg_evalpk(0.0), avg_enc(0.0), avg_dec(0.0);

	// plaintext
	for(usint i=0; i<iter; i++)
	{

		std::cout << "starting iter " << i << std::endl;

		DCRTPoly ptext(bug, ilDCRTParams, COEFFICIENT);

		Poly ptextInterp = ptext.CRTInterpolate();

		// circuit outputs
		RingMatDCRT evalBf(DCRTPoly::Allocator(ilDCRTParams, EVALUATION), 1, m);  //evaluated Bs
		RingMatDCRT evalCf(DCRTPoly::Allocator(ilDCRTParams, EVALUATION), 1, m);  // evaluated Cs
		RingMatDCRT ctCA(DCRTPoly::Allocator(ilDCRTParams, EVALUATION), 1, m); // CA

		// secret key corresponding to the circuit output
		RingMatDCRT sk(zero_alloc, 2, m);

		// decrypted text
		DCRTPoly dtext(ilDCRTParams, EVALUATION, true);

		double start, finish;

		ptext.SwitchFormat();
		TIC(t1);
		sender.Encrypt(ilDCRTParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1); // Cin and c1 are the ciphertext
		avg_enc += TOC(t1);

		ctCA = ctCin.ExtractRow(0);  // CA is A^T * s + e 0,A

		TIC(t1);
		receiver.EvalCT(ilDCRTParams, publicElementB, x, ctCin.ExtractRows(1, ell + 1), &y, &evalCf);
		avg_evalct += TOC(t1);

		TIC(t1);
		pkg.EvalPK(ilDCRTParams, publicElementB, &evalBf);
		avg_evalpk += TOC(t1);

		TIC(t1);
		pkg.KeyGen(ilDCRTParams, trapdoorA.first, evalBf, pubElemBeta, trapdoorA.second, dgg, &sk);
		avg_keygen += TOC(t1);
	//	CheckSecretKeyKPDCRT(m, trapdoorA.first, evalBf, sk, pubElemBeta);

		TIC(t1);
		receiver.Decrypt(ilDCRTParams, sk, ctCA, evalCf, c1, &dtext);
		Poly dtextPoly(dtext.CRTInterpolate());
		receiver.Decode(&dtextPoly);
		avg_dec += TOC(t1);

		if(ptextInterp  != dtextPoly){
			std::cout << "Decryption fails at iteration: " << i << std::endl;
			return 0;
		}

		std::cout << "ended iter " << i << std::endl;
	}

	std::cout << "Encryption is successful after " << iter << " iterations!\n";
	std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
	std::cout << "Average ciphertext evaluation time : " << "\t" << (avg_evalct)/iter << " ms" << std::endl;
	std::cout << "Average public key evaluation time : " << "\t" << (avg_evalpk)/iter << " ms" << std::endl;
	std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
	std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;


	delete[] x;
	return 0;

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


