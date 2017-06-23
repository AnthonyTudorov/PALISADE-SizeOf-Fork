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
//	const usint m = 64;
//	const usint p = 129;

	string filename;
	if( argc != 2 )
		filename = "src/circuit/demo/sample-matrix-mult.acirc";
	else
		filename = string(argv[1]);

	usint m = 22;
	usint p = 89;
	BigBinaryInteger modulusP(p);
	BigBinaryInteger modulusQ("955263939794561");
	BigBinaryInteger squareRootOfRoot("941018665059848");
	BigBinaryInteger bigmodulus("80899135611688102162227204937217");
	BigBinaryInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP,PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP),batchSize));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(params, encodingParams, 8, stdDev);

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();
	cc.EvalMultKeyGen(kp.secretKey);
	cc.EvalSumKeyGen(kp.secretKey);

	// PARSE THE GRAPH
	pdriver driver(false);

	auto res = driver.parse(filename);
	if( res != 0 ) {
		cout << "Parse error" << endl;
		return 1;
	}

	PalisadeCircuit<ILVector2n>	cir(cc, driver.graph);

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding packedArray1(vectorOfInts1);

	std::cout << "Input array 1 \n\t" << packedArray1 << std::endl;

	std::vector<usint> vectorOfInts2 = { 1,2,3,2,1,2,1,2,0,0 };
	PackedIntPlaintextEncoding packedArray2(vectorOfInts2);

	std::cout << "Input array 2 \n\t" << packedArray2 << std::endl;

	// construct matrix for first vector
	Matrix<IntPlaintextEncoding> scalarMatrix1([](){return make_unique<IntPlaintextEncoding>();},
			1,vectorOfInts1.size());
	for( size_t c=0; c<vectorOfInts1.size(); c++ ) {
		scalarMatrix1(0,c) = { vectorOfInts1[c] };
	}

	// construct matrix for second vector
	Matrix<IntPlaintextEncoding> scalarMatrix2([](){return make_unique<IntPlaintextEncoding>();},
			vectorOfInts2.size(), 1);
	for( size_t r=0; r<vectorOfInts2.size(); r++ ) {
		scalarMatrix2(r,0) = { vectorOfInts2[r] };
	}

	// construct bit matrix for first vector
	Matrix<IntPlaintextEncoding> bitMatrix1([](){return make_unique<IntPlaintextEncoding>();},
			1,vectorOfInts1.size());
	for( size_t c=0; c<vectorOfInts1.size(); c++ ) {
		bitMatrix1(0,c) = IntPlaintextEncoding(vectorOfInts1[c]);
		bitMatrix1(0,c).resize( cc.GetRingDimension() );
	}

	// construct bit matrix for second vector
	Matrix<IntPlaintextEncoding> bitMatrix2([](){return make_unique<IntPlaintextEncoding>();},
			vectorOfInts2.size(), 1);
	for( size_t r=0; r<vectorOfInts2.size(); r++ ) {
		bitMatrix2(r,0) = IntPlaintextEncoding(vectorOfInts2[r]);
		bitMatrix2(r,0).resize( cc.GetRingDimension() );
	}

	vector<TimingInfo>	times;
	cc.StartTiming(&times);
	cc.StopTiming();
	{
		cout << "SCALAR ENCODING" << endl;
		shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> A = cc.EncryptMatrix(kp.publicKey, scalarMatrix1);
		shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> B = cc.EncryptMatrix(kp.publicKey, scalarMatrix2);

		// evaluate in a circuit
		CircuitIO<ILVector2n> inputs;
		inputs[0] = A;
		inputs[1] = B;

		//cc.ResetTiming();
		cc.ResumeTiming();

		CircuitIO<ILVector2n> outputs = cir.CircuitEval(inputs);

		cc.StopTiming();

		for( auto& out : outputs ) {
			auto m = out.second.GetIntMatValue();
			Matrix<IntPlaintextEncoding> numerator([](){return make_unique<IntPlaintextEncoding>();},m->GetRows(),m->GetCols());
			Matrix<IntPlaintextEncoding> denominator([](){return make_unique<IntPlaintextEncoding>();},m->GetRows(),m->GetCols());
			cc.DecryptMatrix(kp.secretKey, m, &numerator, &denominator);

			cout << "numerator dimensions: " << numerator.GetRows() << "," << numerator.GetCols() << endl;
			cout << "denominator dimensions: " << denominator.GetRows() << "," << denominator.GetCols() << endl;

			cout << numerator(0,0) << "/" << denominator(0,0) << endl;
		}

		cout << "Timing:" << endl;
		for( auto& t : times ) {
			cout << t << endl;
		}
	}

	{
		cout << "BIT ENCODING" << endl;
		shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> A = cc.EncryptMatrix(kp.publicKey, bitMatrix1);
		shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> B = cc.EncryptMatrix(kp.publicKey, bitMatrix2);

		// evaluate in a circuit
		CircuitIO<ILVector2n> inputs;
		inputs[0] = A;
		inputs[1] = B;

		//cc.ResetTiming();
		cc.ResumeTiming();

		CircuitIO<ILVector2n> outputs = cir.CircuitEval(inputs);

		cc.StopTiming();

		for( auto& out : outputs ) {
			auto m = out.second.GetIntMatValue();
			Matrix<IntPlaintextEncoding> numerator([](){return make_unique<IntPlaintextEncoding>();},m->GetRows(),m->GetCols());
			Matrix<IntPlaintextEncoding> denominator([](){return make_unique<IntPlaintextEncoding>();},m->GetRows(),m->GetCols());
			cc.DecryptMatrix(kp.secretKey, m, &numerator, &denominator);

			cout << "numerator dimensions: " << numerator.GetRows() << "," << numerator.GetCols() << endl;
			cout << "denominator dimensions: " << denominator.GetRows() << "," << denominator.GetCols() << endl;

			cout << numerator(0,0) << "/" << denominator(0,0) << endl;
		}

		cout << "Timing:" << endl;
		for( auto& t : times ) {
			cout << t << endl;
		}
	}

	{
		cout << "EvalLin for PACKED ENCODING" << endl;
		auto A = cc.Encrypt(kp.publicKey, packedArray1);
		auto B = cc.Encrypt(kp.publicKey, packedArray2);

		//cc.ResetTiming();
		cc.ResumeTiming();

		auto result = cc.EvalInnerProduct(A[0], B[0], batchSize);

		PackedIntPlaintextEncoding intArrayNew;

		cc.StopTiming();

		cc.Decrypt(kp.secretKey, {result}, &intArrayNew, false);

		cout << intArrayNew << endl;

		cout << "Timing:" << endl;
		for( auto& t : times ) {
			cout << t << endl;
		}
	}

	return 0;
}
