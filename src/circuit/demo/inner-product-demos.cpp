/**
 * @file inner-product-demos.cpp -- Demonstrates different ways of making inner products
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 * reads file of needed timings; generates timings for estimator
 *
 */

#include "palisade.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"
#include "cryptocontextgen.h"
#include "palisadecircuit.h"
#include "parsedriver.h"

using namespace lbcrypto;

#include <fstream>
using namespace std;

#include "circuitnode.cpp"
#include "circuitgraph.cpp"
#include "circuitinput.cpp"

namespace lbcrypto {
template class CircuitGraphWithValues<ILVector2n>;
template class CircuitNodeWithValue<ILVector2n>;
template class CircuitObject<ILVector2n>;
}

int
main(int argc, char *argv[])
{
	string filename;
	if( argc != 2 )
		filename = "src/circuit/demo/sample-matrix-mult.acirc";
	else
		filename = string(argv[1]);

	// PARSE THE GRAPH
	pdriver driver(false);

	auto res = driver.parse(filename);
	if( res != 0 ) {
		cout << "Parse error" << endl;
		return 1;
	}

	std::vector<usint> vectorOfInts;

	for( int i=0; i<64; i++ )
		vectorOfInts.push_back(i%16);

	cout << "Inner product of this vector with itself:" << endl << "[ ";
	for( size_t i=0; i<64; i++ ) {
		cout << vectorOfInts[i] << " ";
		if( i == 31 ) cout << endl << "  ";
	}
	cout << "]" << endl;

	cout << "Inner Product using SCALAR ENCODING" << endl;
	{
		usint relinWindow = 16;
		float stdDev = 4;
		usint assurance = 144;
		usint m = 1811;
		usint ptm = 10400;

		BigBinaryInteger modulus("147573952589676481307");
		BigBinaryInteger rootUnity("36745553101704677056");
		BigBinaryInteger bigModulus("178405961588244985132285746181186892047872001");
		BigBinaryInteger bigRootUnity("115052626582232218836484393614104952128652495");

		shared_ptr<ILParams> params( new ILParams(m, modulus, rootUnity, bigModulus, bigRootUnity) );

		shared_ptr<LPCryptoParametersBV<ILVector2n>> cparams( new LPCryptoParametersBV<ILVector2n>(
				params,
				BigBinaryInteger(ptm),
				stdDev,
				assurance,
				1.006, // securityLevel,
				relinWindow, // Relinearization Window
				OPTIMIZED, //Mode of noise generation
				1) );

		shared_ptr<LPPublicKeyEncryptionScheme<ILVector2n>> scheme( new LPPublicKeyEncryptionSchemeBV<ILVector2n>() );

		shared_ptr<CryptoContext<ILVector2n>> cc = shared_ptr<CryptoContext<ILVector2n>>( new CryptoContext<ILVector2n>(cparams, scheme) );
		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		LPKeyPair<ILVector2n> kp = cc->KeyGen();
		cc->EvalMultKeyGen(kp.secretKey);
		cc->EvalSumKeyGen(kp.secretKey);

		PalisadeCircuit<ILVector2n>	cir(cc, driver.graph);

		// construct matrix for first vector
		Matrix<IntPlaintextEncoding> scalarMatrix1([](){return make_unique<IntPlaintextEncoding>();},
				1,vectorOfInts.size());
		for( size_t c=0; c<vectorOfInts.size(); c++ ) {
			scalarMatrix1(0,c) = { vectorOfInts[c] };
		}

		// construct matrix for second vector
		Matrix<IntPlaintextEncoding> scalarMatrix2([](){return make_unique<IntPlaintextEncoding>();},
				vectorOfInts.size(), 1);
		for( size_t r=0; r<vectorOfInts.size(); r++ ) {
			scalarMatrix2(r,0) = { vectorOfInts[r] };
		}

		shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> A = cc->EncryptMatrix(kp.publicKey, scalarMatrix1);
		shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> B = cc->EncryptMatrix(kp.publicKey, scalarMatrix2);

		// evaluate in a circuit
		CircuitIO<ILVector2n> inputs;
		inputs[0] = A;
		inputs[1] = B;

		vector<TimingInfo>	times;
		cc->StartTiming(&times);

		CircuitIO<ILVector2n> outputs = cir.CircuitEval(inputs);

		cc->StopTiming();

		for( auto& out : outputs ) {
			auto m = out.second.GetIntMatValue();
			Matrix<IntPlaintextEncoding> numerator([](){return make_unique<IntPlaintextEncoding>();},m->GetRows(),m->GetCols());
			Matrix<IntPlaintextEncoding> denominator([](){return make_unique<IntPlaintextEncoding>();},m->GetRows(),m->GetCols());
			cc->DecryptMatrix(kp.secretKey, m, &numerator, &denominator);

			cout << "INNER PRODUCT IS: " << numerator(0,0)[0] << endl;
		}

		cout << "Timing, using circuit eval of " << times[0].operation << ", is " << times[0].timeval << "ms" << endl;
	}
	cout << endl << endl;

	cout << "Inner Product using BIT ENCODING" << endl;
	{
		usint relinWindow = 16;
		float stdDev = 4;
		usint assurance = 144;
		usint m = 1559;
		usint ptm = 512;

		BigBinaryInteger modulus("144115188075962143");
		BigBinaryInteger rootUnity("62176233231091969");
		BigBinaryInteger bigModulus("170141183460469231731687303715884605441");
		BigBinaryInteger bigRootUnity("145253131385025115938671309869900439301");

		shared_ptr<ILParams> params( new ILParams(m, modulus, rootUnity, bigModulus, bigRootUnity) );

		shared_ptr<LPCryptoParametersBV<ILVector2n>> cparams( new LPCryptoParametersBV<ILVector2n>(
				params,
				BigBinaryInteger(ptm),
				stdDev,
				assurance,
				1.006, // securityLevel,
				relinWindow, // Relinearization Window
				OPTIMIZED, //Mode of noise generation
				1) );

		shared_ptr<LPPublicKeyEncryptionScheme<ILVector2n>> scheme( new LPPublicKeyEncryptionSchemeBV<ILVector2n>() );

		shared_ptr<CryptoContext<ILVector2n>> cc = shared_ptr<CryptoContext<ILVector2n>>( new CryptoContext<ILVector2n>(cparams, scheme) );
		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		LPKeyPair<ILVector2n> kp = cc->KeyGen();
		cc->EvalMultKeyGen(kp.secretKey);
		cc->EvalSumKeyGen(kp.secretKey);

		PalisadeCircuit<ILVector2n>	cir(cc, driver.graph);

		// construct bit matrix for first vector
		Matrix<IntPlaintextEncoding> bitMatrix1([](){return make_unique<IntPlaintextEncoding>();},
				1,vectorOfInts.size());
		for( size_t c=0; c<vectorOfInts.size(); c++ ) {
			bitMatrix1(0,c) = IntPlaintextEncoding(vectorOfInts[c]);
			bitMatrix1(0,c).resize( cc->GetRingDimension() );
		}

		// construct bit matrix for second vector
		Matrix<IntPlaintextEncoding> bitMatrix2([](){return make_unique<IntPlaintextEncoding>();},
				vectorOfInts.size(), 1);
		for( size_t r=0; r<vectorOfInts.size(); r++ ) {
			bitMatrix2(r,0) = IntPlaintextEncoding(vectorOfInts[r]);
			bitMatrix2(r,0).resize( cc->GetRingDimension() );
		}

		shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> A = cc->EncryptMatrix(kp.publicKey, bitMatrix1);
		shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> B = cc->EncryptMatrix(kp.publicKey, bitMatrix2);

		// evaluate in a circuit
		CircuitIO<ILVector2n> inputs;
		inputs[0] = A;
		inputs[1] = B;

		vector<TimingInfo>	times;
		cc->StartTiming(&times);

		CircuitIO<ILVector2n> outputs = cir.CircuitEval(inputs);

		cc->StopTiming();

		for( auto& out : outputs ) {
			auto m = out.second.GetIntMatValue();
			Matrix<IntPlaintextEncoding> numerator([](){return make_unique<IntPlaintextEncoding>();},m->GetRows(),m->GetCols());
			Matrix<IntPlaintextEncoding> denominator([](){return make_unique<IntPlaintextEncoding>();},m->GetRows(),m->GetCols());
			cc->DecryptMatrix(kp.secretKey, m, &numerator, &denominator);

			uint32_t ptm = cc->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();
			cout << "INNER PRODUCT IS: " << numerator(0,0).EvalToInt(ptm) << endl;
		}

		cout << "Timing, using circuit eval of " << times[0].operation << ", is " << times[0].timeval << "ms" << endl;
	}
	cout << endl << endl;

	cout << "Inner Product using PACKED ENCODING" << endl;
	{
		usint relinWindow = 16;
		float stdDev = 4;
		usint assurance = 144;
		usint batchSize = 64;
		usint m = 1733;
		usint ptm = 10399;

		BigBinaryInteger modulus("1152921504606909071");
		BigBinaryInteger rootUnity("44343872016735288");
		BigBinaryInteger bigModulus("10889035741470030830827987437816582848513");
		BigBinaryInteger bigRootUnity("5879632101734955395039618227388702592012");

		PackedIntPlaintextEncoding::SetParams(ptm, m);

		shared_ptr<ILParams> params( new ILParams(m, modulus, rootUnity, bigModulus, bigRootUnity) );

		shared_ptr<EncodingParams> encodingParams(new EncodingParams(ptm,PackedIntPlaintextEncoding::GetAutomorphismGenerator(ptm),batchSize));

		shared_ptr<LPCryptoParametersBV<ILVector2n>> cparams( new LPCryptoParametersBV<ILVector2n>(
				params,
				encodingParams,
				stdDev,
				assurance,
				1.006, // securityLevel,
				relinWindow, // Relinearization Window
				OPTIMIZED, //Mode of noise generation
				1) );

		shared_ptr<LPPublicKeyEncryptionScheme<ILVector2n>> scheme( new LPPublicKeyEncryptionSchemeBV<ILVector2n>() );

		shared_ptr<CryptoContext<ILVector2n>> cc = shared_ptr<CryptoContext<ILVector2n>>( new CryptoContext<ILVector2n>(cparams, scheme) );
		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		LPKeyPair<ILVector2n> kp = cc->KeyGen();
		cc->EvalMultKeyGen(kp.secretKey);
		cc->EvalSumKeyGen(kp.secretKey);

		PackedIntPlaintextEncoding packedArray1(vectorOfInts);
		PackedIntPlaintextEncoding packedArray2(vectorOfInts);

		auto A = cc->Encrypt(kp.publicKey, packedArray1);
		auto B = cc->Encrypt(kp.publicKey, packedArray2);

		vector<TimingInfo>	times;
		cc->StartTiming(&times);

		auto result = cc->EvalInnerProduct(A[0], B[0], batchSize);

		cc->StopTiming();

		PackedIntPlaintextEncoding intArrayNew;
		cc->Decrypt(kp.secretKey, {result}, &intArrayNew, false);

		cc->StopTiming();

		cout << "INNER PRODUCT IS: " << intArrayNew[0] << endl;

		cout << "Timing, using " << times[0].operation << ", is " << times[0].timeval << "ms" << endl;
	}

	return 0;
}
