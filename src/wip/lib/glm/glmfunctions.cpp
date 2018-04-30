/**
 * @file glmfunctions.cpp Represents and defines generalized linear method in Palisade with regression capabilities.
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

#include "glmfunctions.h"

#ifdef MEASURE_TIMING
timingParams timingClient;
timingParams timingServer;
#endif


///////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////  Server SIDE  /////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////

void GLMServerXW(GLMContext &context, pathList &path, glmParams & params) {

	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> beta;
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> xTb;
#ifdef MEASURE_TIMING
	double start, finish;
	start = currentDateTime();
#endif
	for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
/*
		string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt";
		string pkFileName = path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt";

		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
		cc.push_back(cct);

		cc[k]->Enable(ENCRYPTION);
		cc[k]->Enable(SHE);

		size_t m = cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

		DeserializeEvalSum(cc[k], esFileName);
		DeserializeEvalMult(cc[k], emFileName);

		string pathToFile;
		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-" + path.ciphertextXFileName + "-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xt = DeserializeCiphertext(cc[k], pathToFile);
		x.push_back(xt);
*/
		string pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextWFileName+"-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> bt = DeserializeCiphertext(context.cc[k], pathToFile);
		beta.push_back(bt);
	}
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.read[0] = timingServer.read[0] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif

    for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
        shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTbt = MultiplyWTransX(context.cc[k], context.x[k], beta[k]);
        xTb.push_back(xTbt);
    }

#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.process[0] = timingServer.process[0] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
    for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {

    	string xTbPath = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextXWFileName+"-" + std::to_string(k) + ".txt";
    	SerializeCiphertext(xTb[k], xTbPath);
    }
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.write[0] = timingServer.write[0] + (finish - start);
#endif
}

void GLMServerXTSX(GLMContext &context, pathList &path, glmParams & params){

//	vector<CryptoContext<DCRTPoly>> cc;
//	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> x;
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> SC;
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C0;
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C1;

#ifdef MEASURE_TIMING
	double start, finish;
	start = currentDateTime();
#endif
	for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
/*
		string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt";
//		string pkFileName = path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt";

		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
		cc.push_back(cct);

		cc[k]->Enable(ENCRYPTION);
		cc[k]->Enable(SHE);

		size_t m = cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

		DeserializeEvalSum(cc[k], esFileName);
		DeserializeEvalMult(cc[k], emFileName);

		string pathToFile;
		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextXFileName+ "-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xt = DeserializeCiphertext(cc[k], pathToFile);
		x.push_back(xt);
*/
		string pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+ path.ciphertextSFileName +"-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> SCt = DeserializeCiphertext(context.cc[k], pathToFile);
		SC.push_back(SCt);
	}
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.read[1] = timingServer.read[1] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
	for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTSt = MultiplyXTransS(context.cc[k], context.x[k], SC[k]);
		C0.push_back(xTSt);
	}

	for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTSxt = MultiplyXTransSX(context.cc[k], context.x[k], C0[k]);
		C1.push_back(xTSxt);
	}
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.process[1] = timingServer.process[1] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
    for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {

		string C1Path = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextC1FileName+"-" + std::to_string(k) + ".txt";
		SerializeCiphertext(C1[k], C1Path);
    }
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.write[1] = timingServer.write[1] + (finish - start);
#endif

}

void GLMServerComputeRegressor(GLMContext &context, pathList &path, glmParams & params){

//	vector<CryptoContext<DCRTPoly>> cc;

	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> w;
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C1;
//	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> x;

	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> muC;
//	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> y;

	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C1C2;

#ifdef MEASURE_TIMING
	double start, finish;
	start = currentDateTime();
#endif
	for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
/*
		string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt";
		string pkFileName = path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt";
		string skFileName = path.keyDir+"/"+path.keyfileName+"-private" + std::to_string(k) + ".txt";


		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
		cc.push_back(cct);

		cc[k]->Enable(ENCRYPTION);
		cc[k]->Enable(SHE);

		size_t m = cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

		DeserializeEvalSum(cc[k], esFileName);
		DeserializeEvalMult(cc[k], emFileName);

		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextXFileName+"-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xt = DeserializeCiphertext(cc[k], pathToFile);
		x.push_back(xt);

		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+ path.ciphertextYFileName +"-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yt = DeserializeCiphertext(cc[k], pathToFile);
		y.push_back(yt);

*/
		string pathToFile;
		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextWFileName+"-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> wt = DeserializeCiphertext(context.cc[k], pathToFile);
		w.push_back(wt);

		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-" + path.ciphertextC1FileName + "-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C1t = DeserializeCiphertext(context.cc[k], pathToFile);
		C1.push_back(C1t);

		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextMUFileName+"-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> muCt = DeserializeCiphertext(context.cc[k], pathToFile);
		muC.push_back(muCt);
	}
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.read[2] = timingServer.read[2] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
    vector<NativeInteger> primeList;
    for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		size_t m = context.cc[k]->GetCyclotomicOrder(); // params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	uint64_t prime = context.cc[k]->GetEncodingParams()->GetPlaintextModulus();
    	primeList.push_back(prime);
    }

    auto zeroAllocPacking = [=]() { return context.cc[0]->MakePackedPlaintext({0}); };
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C2;
	for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C2t = MultiplyXAddYMu(context.cc[k], context.y[k], context.x[k], muC[k]);
		C2.push_back(C2t);
	}

	for(size_t k=0; k<primeList.size(); k++){

		auto zeroAllocRationalCiphertext = [=]() { return context.cc[k]; };
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C1C2t = MultiplyC1C2(context.cc[k], C1[k], C2[k]);
		C1C2.push_back(C1C2t);
	}

	for(size_t k=0; k<primeList.size(); k++){
		C1C2[k] = context.cc[k]->EvalAddMatrix(C1C2[k], w[k]);
	}

#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.process[2] = timingServer.process[2] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
	for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {

    	string C1C2Path = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextC1C2FileName+"-" + std::to_string(k) + ".txt";
		SerializeCiphertext(C1C2[k], C1C2Path);
    }
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingServer.write[2] = timingServer.write[2] + (finish - start);
#endif

}

///////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////  CLIENT SIDE  /////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////

usint ComputeCyclotomicRing( glmParams & params){

	usint m = 8;
	usint batchSize = 4;

	NativeInteger p = FirstPrime<NativeInteger>(params.PLAINTEXTBITSIZE, m);
	PlaintextModulus modulusP = p.ConvertToInt();
	EncodingParams encodingParams(new EncodingParamsImpl(modulusP, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	double sigma = 3.2;
	double rootHermiteFactor = 1.006;
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns( encodingParams, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED, 3, 30, 60);

	return cc->GetCyclotomicOrder();
}
/*
void threadTest(CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &kp){

    std::vector<uint64_t> vectorOfInts1;
//    for(size_t i=0; i<cc->GetRingDimension(); i++)
    	vectorOfInts1.push_back(0);

    Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

    vector<Ciphertext<DCRTPoly>> c1_;
    vector<Ciphertext<DCRTPoly>> c2_;
    vector<Ciphertext<DCRTPoly>> c3_;
    vector<Plaintext> res_;

    size_t M = 20;

    for(size_t i=0; i<M; i++){
    	Ciphertext<DCRTPoly> c1 = cc->Encrypt(kp.publicKey, intArray1);
    	Ciphertext<DCRTPoly> c2 = cc->Encrypt(kp.publicKey, intArray1);

    	c1_.push_back(c1);
    	c2_.push_back(c2);

//    	Ciphertext<DCRTPoly> c3(new CiphertextImpl<DCRTPoly>(cc));
//   	c3_.push_back(c3);
    }
    Ciphertext<DCRTPoly> t  = cc->EvalMult(c1_[0], c2_[0]);
#pragma omp parallel for shared(M, cc, c1_, c2_) num_threads(8)
    for(size_t i=0; i<M; i++){
    	Ciphertext<DCRTPoly> c3 = cc->EvalMult(c1_[i], c2_[i]);
#pragma omp critical
{
    	c3_.push_back(c3);
}
    }

    for(size_t i=0; i<M; i++){
    	Plaintext res;
    	cc->Decrypt(kp.secretKey, c3_[i], &res);
    	res_.push_back(res);
    }

    for(size_t i=0; i<M; i++){
    	cout << "Test " << i << endl;
    	cout << res_[i] << endl;

//    	if(intArray1 == res_[i])
//    		cout << "Test-" << i << "\t\t" << endl;
//    	else
//    		cout << "Test-" << i << "\t\t0" << endl;

    }
}
*/
void GLMKeyGen(pathList &path, glmParams & params) {

	usint m = ComputeCyclotomicRing(params);

	cout << "Computed Required Cyc Ring\t" << m << endl;

	vector<NativeInteger> primeList;
	MessagePrimeListGen(primeList, m, params);

	std::cout << "Writing Prime Space List to a file...";
	WritePlaintextSpacePrimes(path.keyDir, path.keyfileName, primeList);
	std::cout << "Completed" << std::endl;

	for (size_t k = 0; k < primeList.size(); k++) {

//		shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT = CiphertextDCRTParamGen(primeList[k], params);
		EncodingParams encodingParams = PlaintextEncodingParamGen(primeList[k], m, params);

//		float stdDev = 4;
//		CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGV(paramsDCRT, encodingParams, 8, stdDev);
		double sigma = 3.2;
		double rootHermiteFactor = 1.006;
//		size_t primeModulus = primeList[k].ConvertToInt();
		CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns( encodingParams, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED, 3, 30, 60);


		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		cout << "m      = " << cc->GetCyclotomicOrder() << endl;
		cout << "n      = " << cc->GetRingDimension() << endl;
		cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << endl;


		////////////////////////////////////////////////////////////
		// Key Generation and Serialization
		////////////////////////////////////////////////////////////

		std::cout << "Generating public and private keys...";
		LPKeyPair<DCRTPoly> kp = cc->KeyGen();
		std::cout << "Completed" << std::endl;

		std::cout << "Serializing public and private keys...";
		SerializePublicKey(kp.publicKey, path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt");
		SerializePrivateKey(kp.secretKey, path.keyDir+"/"+path.keyfileName+"-private" + std::to_string(k) + ".txt");
		std::cout << "Completed" << std::endl;

		////////////////////////////////////////////////////////////
		// EvalMult and EvalSum Keys and Serialization
		////////////////////////////////////////////////////////////

		std::cout << "Generating multiplication evaluation key...";
		cc->EvalMultKeyGen(kp.secretKey);
		const auto evalMultKey = cc->GetEvalMultKeyVector(kp.secretKey->GetKeyTag());
		std::cout << "Completed" << std::endl;

		std::cout << "Serializing multiplication evaluation key...";
		SerializeMultEvalKey(cc, evalMultKey, path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt");
		std::cout << "Completed" << std::endl;

		// EvalSumKey
		std::cout << "Generating summation evaluation keys...";
		cc->EvalSumKeyGen(kp.secretKey);
		auto evalSumKey = cc->GetEvalSumKeyMap(kp.secretKey->GetKeyTag());
		std::cout << "Completed" << std::endl;

		std::cout << "Serializing summation evaluation keys...";
		SerializeSumEvalKey(cc, evalSumKey, path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt");
		std::cout << "Completed" << std::endl;

		std::cout << "Serializing CrytoContext...";
		SerializeContext(cc, path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt");
		std::cout << "Completed" << std::endl;


//		threadTest(cc, kp);
	}

}

void GLMEncrypt(GLMContext &context, pathList &path, glmParams &params)
{
    string dataFileName = path.plaintextDataDir+"/"+path.plaintextDataFileName;

    vector<string> headers;
    vector<vector<double>> dataColumns;

    cout << "\nLOADING THE DATA\n" << std::endl;

    // Read csv file into a two-dimensional vector
    cout << "Reading the CSV file...";
    ReadCSVFile(dataFileName, headers, dataColumns);
    std::cout << "Completed" << std::endl;

    cout << "Writing Meta Data file...";
    string metaDataPath = path.ciphertextDataDir + "/lr_data_" + path.ciphertextDataFileName;
    WriteMetaData(metaDataPath, headers, dataColumns);
    std::cout << "Completed" << std::endl;

    vector<BigInteger> primeList;
    ReadPlaintextSpacePrimes(path.keyDir, path.keyfileName, primeList);

	uint32_t numRegressors = headers.size()-1;
//	cout<<"Num Regressors: " << numRegressors << endl;

	//Compute the row size of the data matrix
	const size_t dataEntrySize = dataColumns[0].size();
	size_t dataMatrixRowSize;

    vector<vector<double>> xPVecDouble, yPVecDouble;
    vector<Matrix<BigInteger>> xPMatVec;
    vector<Matrix<BigInteger>> yPMatVec;

    ParseData(dataColumns, xPVecDouble, yPVecDouble);

    DataToCRT(xPVecDouble, xPMatVec, primeList, params.PRECISIONDECIMALSIZEX, params);
    DataToCRT(yPVecDouble, yPMatVec, primeList, params.PRECISIONDECIMALSIZE, params);

    // Key deserialization is done here
    for(size_t k = 0; k < primeList.size(); k++) {

		std::cout << "\nDESERIALIZATION/ENCRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;
		string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
		string bkFileName = path.keyDir+"/"+path.keyfileName+"-beta" + std::to_string(k) + ".txt";
		string pkFileName = path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt";
		string skFileName = path.keyDir+"/"+path.keyfileName+"-private" + std::to_string(k) + ".txt";
		string ecFileName = path.keyDir+"/"+path.keyfileName+"-encoding" + std::to_string(k) + ".txt";

		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cc = DeserializeContext(ccFileName);
		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		size_t m = cc->GetCyclotomicOrder();// params.CYCLOTOMICM;
		EncodingParams encodingParams = cc->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);
        // Transform the data and store in the Packed Encoding format

		dataMatrixRowSize = dataEntrySize/cc->GetRingDimension(); //params.ENTRYSIZE;
		if(dataEntrySize%cc->GetRingDimension() != 0)
			dataMatrixRowSize++;

        std::cout << "Encoding the data...";

        auto zeroAllocPlaintext = [=]() { return cc->MakePackedPlaintext({0}); };

        Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAllocPlaintext, dataMatrixRowSize, numRegressors);
        Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAllocPlaintext, dataMatrixRowSize, 1);

        ConvertMatrixBigIntegerToPlaintextEncoding(cc, xPMatVec[k], xP);
        ConvertMatrixBigIntegerToPlaintextEncoding(cc, yPMatVec[k], yP);

        Matrix<Plaintext> bP = Matrix<Plaintext>(zeroAllocPlaintext, 1, numRegressors);
        std::cout << "Completed" << std::endl;

	    std::vector<uint64_t> vectorOfInts1;
	    for(size_t i=0; i<cc->GetRingDimension(); i++){
	    	vectorOfInts1.push_back(0);
	    }

		Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
	    for(size_t j=0; j<numRegressors; j++){
	    	bP(0, j) = intArray1;
	    }

		// Deserialize the public key
		std::cout << "Deserializing the public key...";
		LPPublicKey<DCRTPoly> pk = DeserializePublicKey(cc, pkFileName);
		std::cout << "Completed" << std::endl;

		std::cout << "Deserializing the private key...";
		LPPrivateKey<DCRTPoly> sk = DeserializePrivateKey(cc, skFileName);
		std::cout << "Completed" << std::endl;

		// Packing and encryption
		std::cout << "Batching/encrypting X...";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xC = cc->EncryptMatrix(pk, xP);
		std::cout << "Completed" << std::endl;
		std::cout << "Batching/encrypting y...";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yC = cc->EncryptMatrix(pk, yP);
		std::cout << "Completed" << std::endl;
		std::cout << "Batching/encrypting Beta...";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> bC = cc->EncryptMatrix(pk, bP);
		std::cout << "Completed" << std::endl;

		// Serialization
		Serialized ctxtSer;
		ctxtSer.SetObject();

		std::cout << "Serializing Encrypted X...";
		SerializeCiphertext(xC, path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextXFileName+"-" + std::to_string(k) + ".txt");
		std::cout << "Completed" << std::endl;

		std::cout << "Serializing Encrypted y...";
		SerializeCiphertext(yC, path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextYFileName+"-" + std::to_string(k) + ".txt");
		std::cout << "Completed" << std::endl;

		std::cout << "Serializing Encrypted Beta...";
		SerializeCiphertext(bC, path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextWFileName+"-" + std::to_string(k) + ".txt");
		std::cout << "Completed" << std::endl;
	}
}

void GLMClientLink(GLMContext &context, pathList &path, glmParams & params, const string &regAlgorithm){

//	vector<CryptoContext<DCRTPoly>> cc;
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> xw;
//	vector<LPPublicKey<DCRTPoly>> pk;
//	vector<LPPrivateKey<DCRTPoly>> sk;
//	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>>  yC;

#ifdef MEASURE_TIMING
	double start, finish;
	start = currentDateTime();
#endif
	for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
/*
		string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt";
		string skFileName = path.keyDir+"/"+path.keyfileName+"-private" + std::to_string(k) + ".txt";
		string pkFileName = path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt";


		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
		cc.push_back(cct);

		cc[k]->Enable(ENCRYPTION);
		cc[k]->Enable(SHE);

		size_t m = cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

		LPPublicKey<DCRTPoly> pkt = DeserializePublicKey(cc[k], pkFileName);
		pk.push_back(pkt);

		LPPrivateKey<DCRTPoly> skt = DeserializePrivateKey(cc[k], skFileName);
		sk.push_back(skt);

		DeserializeEvalSum(cc[k], esFileName);
		DeserializeEvalMult(cc[k], emFileName);
*/
		string pathToFile;
		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+ path.ciphertextXWFileName+ "-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xwt = DeserializeCiphertext(context.cc[k], pathToFile);
		xw.push_back(xwt);
/*
		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-" + path.ciphertextYFileName +"-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yt = DeserializeCiphertext(cc[k], pathToFile);
		yC.push_back(yt);
*/
	}
#ifdef MEASURE_TIMING
	finish = currentDateTime();
	timingClient.read[0] = timingClient.read[0] + (finish - start);
#endif

#ifdef MEASURE_TIMING
    double start2 = currentDateTime();
#endif
	auto zeroAllocBigInteger = [=]() { return BigInteger(); };
	auto zeroAllocPacking = [=]() { return context.cc[0]->MakePackedPlaintext({0}); };
	size_t dataMatrixRowSize = (*xw[0]).GetRows();

    vector<Matrix<Plaintext>> xTbCRT;
    for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {

		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	shared_ptr<Matrix<Plaintext>> numeratorxTb (new Matrix<Plaintext>(zeroAllocPacking, dataMatrixRowSize, 1));
    	context.cc[k]->DecryptMatrixNumerator(context.sk[k], xw[k], &numeratorxTb);
    	xTbCRT.push_back(*numeratorxTb);
    }

    shared_ptr<Matrix<BigInteger>> wTb (new Matrix<BigInteger>(zeroAllocBigInteger));
    (*wTb).SetSize(dataMatrixRowSize, context.cc[0]->GetRingDimension());

    vector<NativeInteger> primeList;
    for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	uint64_t prime = context.cc[k]->GetEncodingParams()->GetPlaintextModulus();
    	primeList.push_back(prime);
    }
    start = currentDateTime();
    size_t colIndex = 0;
    CRTInterpolateMatrixEntrySelect(xTbCRT, *wTb, primeList, colIndex);
    finish = currentDateTime();
    cout << "CRT1\t" << finish-start << endl;
    vector<shared_ptr<Matrix<Plaintext>>> mu;
    vector<shared_ptr<Matrix<Plaintext>>> S;
    vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> muC;
    vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> SC;

    ////////////
    vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> xTS;
    vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> xTSx;
    vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> xwSyMu;
    start = currentDateTime();
    size_t numCol;
    size_t numRow;
    ReadMetaData(path.ciphertextDataDir, path.ciphertextDataFileName, numCol, numRow);
	LinkFunctionLogisticSigned(context.cc, *wTb, mu, S, numRow, primeList, regAlgorithm, params);
    finish = currentDateTime();
    cout << "Link\t" << finish-start << endl;

	Matrix<BigInteger> muBigInteger(Matrix<BigInteger>(zeroAllocBigInteger, dataMatrixRowSize, context.cc[0]->GetRingDimension()));
	Matrix<BigInteger> yBigInteger(Matrix<BigInteger>(zeroAllocBigInteger, dataMatrixRowSize, context.cc[0]->GetRingDimension()));

	vector<Matrix<Plaintext>> muP;
	for(size_t i=0; i<mu.size(); i++){
		muP.push_back(*mu[i]);
	}
	start = currentDateTime();
	CRTInterpolateMatrixEntrySelect(muP, muBigInteger, primeList, colIndex);
    finish = currentDateTime();
    cout << "CRT2\t" << finish-start << endl;

	start = currentDateTime();
	vector<Matrix<Plaintext>> y;
	for(size_t k=0; k<primeList.size(); k++){
		shared_ptr<Matrix<Plaintext>> yP (new Matrix<Plaintext>(zeroAllocPacking, dataMatrixRowSize, 1));
		context.cc[k]->DecryptMatrixNumerator(context.sk[k], context.y[k], &yP);
		y.push_back(*yP);
	}
    finish = currentDateTime();
    cout << "Dec\t" << finish-start << endl;

	start = currentDateTime();
	CRTInterpolateMatrixEntrySelect(y, yBigInteger, primeList, colIndex);
    finish = currentDateTime();
    cout << "CRT3\t" << finish-start << endl;


	start = currentDateTime();
    for(size_t k = 0; k < primeList.size(); k++) {
		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	auto zeroAllocRationalCiphertext = [=]() { return context.cc[k]; };

 		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> muCt = context.cc[k]->EncryptMatrix(context.pk[k], *(mu[k]));
   		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> SCt = context.cc[k]->EncryptMatrix(context.pk[k], *(S[k]));

    	muC.push_back(muCt);
    	SC.push_back(SCt);
    }
    finish = currentDateTime();
    cout << "Enc\t" << finish-start << endl;

#ifdef MEASURE_TIMING
    double finish2 = currentDateTime();
    timingClient.process[0] = timingClient.process[0] + (finish2 - start2);
#endif

#ifdef MEASURE_TIMING
    start = currentDateTime();
#endif
    for(size_t k = 0; k < primeList.size(); k++) {
		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

		string muCPath = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextMUFileName+"-" + std::to_string(k) + ".txt";
		SerializeCiphertext(muC[k], muCPath);

		string SCPath = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextSFileName+"-" + std::to_string(k) + ".txt";
		SerializeCiphertext(SC[k], SCPath);
    }
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingClient.write[0] = timingClient.write[0] + (finish - start);
#endif
}

void GLMClientRescaleC1(GLMContext &context, pathList &path, glmParams & params){

//	vector<CryptoContext<DCRTPoly>> cc;
//	vector<LPPublicKey<DCRTPoly>> pk;
//	vector<LPPrivateKey<DCRTPoly>> sk;

	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C1;

#ifdef MEASURE_TIMING
	double start, finish;
	start = currentDateTime();
#endif

	for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
/*
		string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt";
		string skFileName = path.keyDir+"/"+path.keyfileName+"-private" + std::to_string(k) + ".txt";
		string pkFileName = path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt";

		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
		cc.push_back(cct);

		cc[k]->Enable(ENCRYPTION);
		cc[k]->Enable(SHE);

		size_t m = cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

		LPPublicKey<DCRTPoly> pkt = DeserializePublicKey(cc[k], pkFileName);
		pk.push_back(pkt);

		LPPrivateKey<DCRTPoly> skt = DeserializePrivateKey(cc[k], skFileName);
		sk.push_back(skt);

		DeserializeEvalSum(cc[k], esFileName);
		DeserializeEvalMult(cc[k], emFileName);
*/
		string pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-" + path.ciphertextC1FileName + "-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C1t = DeserializeCiphertext(context.cc[k], pathToFile);
		C1.push_back(C1t);
	}

	size_t numCol;
    size_t numRow;
    ReadMetaData(path.ciphertextDataDir, path.ciphertextDataFileName, numCol, numRow);

#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingClient.read[1] = timingClient.read[1] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
    vector<NativeInteger> primeList;
    for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	uint64_t prime = context.cc[k]->GetEncodingParams()->GetPlaintextModulus();
    	primeList.push_back(prime);
    }

    vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C1L;
    vector<Matrix<Plaintext>> C1Plaintext;

    auto zeroAllocPacking = [=]() { return context.cc[0]->MakePackedPlaintext({0}); };
    auto zeroAllocBigInteger = [=]() { return BigInteger(); };

    size_t numRegressors = (*C1[0]).GetCols();
	size_t batchSize = context.cc[0]->GetRingDimension(); //params.ENTRYSIZE;
	start = currentDateTime();

//#pragma omp parallel for shared(context, C1, C1Plaintext, zeroAllocPacking, numRegressors) num_threads(8) ordered
    for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){

    	shared_ptr<Matrix<Plaintext>> numeratorC1 (new Matrix<Plaintext>(zeroAllocPacking, numRegressors, numRegressors));
//    	context.cc[k]->DecryptMatrixNumerator(context.sk[k], C1[k], &numeratorC1);

    	for(size_t i=0; i<numRegressors; i++)
    		for(size_t j=0; j<numRegressors; j++)
    			context.cc[k]->Decrypt(context.sk[k], (*C1[k])(i,j).GetNumerator(), &(*numeratorC1)(i,j));


//		#pragma omp ordered
//    	{
    		cout << k << endl;
    		C1Plaintext.push_back(*numeratorC1);
//    	}
    }
    finish = currentDateTime();
    cout << "Dec\t" <<(finish - start) << endl;

    vector<shared_ptr<Matrix<BigInteger>>> C0PlaintextCRTList;

    start = currentDateTime();
    shared_ptr<Matrix<BigInteger>> C1PlaintextCRT (new Matrix<BigInteger>(zeroAllocBigInteger, numRegressors, numRegressors));
    CRTInterpolate(C1Plaintext, *C1PlaintextCRT, primeList);
    finish = currentDateTime();
    cout << "CRT\t" <<(finish - start) << endl;
    auto zeroAllocDouble = [=]() { return double(); };

    start = currentDateTime();
    shared_ptr<Matrix<double>> C1PlaintextCRTDouble (new Matrix<double>(zeroAllocDouble, numRegressors, numRegressors));
    ConvertUnsingedToSigned( *C1PlaintextCRT, *C1PlaintextCRTDouble, primeList);
    DecimalDecrement(*C1PlaintextCRTDouble, *C1PlaintextCRTDouble, params.PRECISIONDECIMALSIZE+params.PRECISIONDECIMALSIZEX*2, params);
    finish = currentDateTime();
    cout << "Dec\t" <<(finish - start) << endl;
//    PrintMatrixDouble(*C1PlaintextCRTDouble);

    start = currentDateTime();
    shared_ptr<Matrix<double>> C1PlaintextCRTDoubleInverse(new Matrix<double>(zeroAllocDouble));
	MatrixInverse(*C1PlaintextCRTDouble, *C1PlaintextCRTDoubleInverse);
	finish = currentDateTime();
	cout << "Inv\t" <<(finish - start) << endl;

	vector<shared_ptr<Matrix<Plaintext>>> C1P;
	start = currentDateTime();
	DecimalIncrement(*C1PlaintextCRTDoubleInverse, *C1PlaintextCRTDoubleInverse, params.PRECISIONDECIMALSIZE, params);
	EncodeC1Matrix(context.cc, C1PlaintextCRTDoubleInverse, C1P, primeList, batchSize);
	finish = currentDateTime();
	cout << "Enc\t" <<(finish - start) << endl;

	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C1C;

	for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C1Ct = context.cc[k]->EncryptMatrix(context.pk[k], *(C1P[k]));
		C1C.push_back(C1Ct);
	}
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingClient.process[1] = timingClient.process[1] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
    for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
		string C1Path = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextC1FileName+"-" + std::to_string(k) + ".txt";
		SerializeCiphertext(C1C[k], C1Path);
    }
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingClient.write[1] = timingClient.write[1] + (finish - start);
#endif
}

vector<double> GLMClientRescaleRegressor(GLMContext &context, pathList &path, glmParams & params){
/*
	vector<CryptoContext<DCRTPoly>> cc;
	vector<LPPublicKey<DCRTPoly>> pk;
	vector<LPPrivateKey<DCRTPoly>> sk;
*/
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C1C2;
#ifdef MEASURE_TIMING
	double start, finish;
	start = currentDateTime();
#endif
	for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
/*
		string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt";
		string skFileName = path.keyDir+"/"+path.keyfileName+"-private" + std::to_string(k) + ".txt";
		string pkFileName = path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt";

		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
		cc.push_back(cct);

		cc[k]->Enable(ENCRYPTION);
		cc[k]->Enable(SHE);

		size_t m = cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

		LPPublicKey<DCRTPoly> pkt = DeserializePublicKey(cc[k], pkFileName);
		pk.push_back(pkt);

		LPPrivateKey<DCRTPoly> skt = DeserializePrivateKey(cc[k], skFileName);
		sk.push_back(skt);

		DeserializeEvalSum(cc[k], esFileName);
		DeserializeEvalMult(cc[k], emFileName);
*/
		string pathToFile;
		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-" + path.ciphertextC1C2FileName + "-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C1C2t = DeserializeCiphertext(context.cc[k], pathToFile);
		C1C2.push_back(C1C2t);

	}
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingClient.read[2] = timingClient.read[2] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
    vector<NativeInteger> primeList;
    for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	uint64_t prime = context.cc[k]->GetEncodingParams()->GetPlaintextModulus();
    	primeList.push_back(prime);
    }

	auto zeroAllocDouble = [=]() { return double(); };
	auto zeroAllocBigInteger = [=]() { return BigInteger(); };
	auto zeroAllocPacking = [=]() { return context.cc[0]->MakePackedPlaintext({0}); };

	size_t numRegressors = (*C1C2[0]).GetCols();
	size_t batchSize = context.cc[0]->GetEncodingParams()->GetBatchSize();

	vector<Matrix<Plaintext>> numeratorC1C2;
	for(size_t k=0; k<primeList.size(); k++){
	    shared_ptr<Matrix<Plaintext>> numeratorC1C2t (new Matrix<Plaintext>(zeroAllocPacking, 1, numRegressors));
	    context.cc[k]->DecryptMatrixNumerator(context.sk[k], C1C2[k], &numeratorC1C2t);
		numeratorC1C2.push_back(*numeratorC1C2t);
	}

	shared_ptr<Matrix<BigInteger>> numeratorC1C2CRT (new Matrix<BigInteger>(zeroAllocBigInteger, 1, numRegressors));
	CRTInterpolate(numeratorC1C2, *numeratorC1C2CRT, primeList);

    shared_ptr<Matrix<double>> C1C2PlaintextCRTDouble (new Matrix<double>(zeroAllocDouble, 1, numRegressors));
    ConvertUnsingedToSigned(*numeratorC1C2CRT, *C1C2PlaintextCRTDouble, primeList);
//  cout << "LAST\n\n";
//	PrintMatrixDouble(*C1C2PlaintextCRTDouble);

    shared_ptr<Matrix<double>> C1C2Fixed(new Matrix<double>(zeroAllocDouble, 1, numRegressors));
    DecimalDecrement(*C1C2PlaintextCRTDouble, *C1C2Fixed, params.PRECISIONDECIMALSIZE*2+params.PRECISIONDECIMALSIZEX, params);

//    PrintMatrixDouble(*C0C1C2Fixed);

    vector<double> regResultRow;
    for(size_t i=0; i<(*C1C2Fixed).GetCols(); i++)
    	regResultRow.push_back((*C1C2Fixed)(0, i));

    vector<shared_ptr<Matrix<Plaintext>>> C1C2FixedP;
    vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> C1C2FixedC;

//    DecimalIncrement(*C1C2Fixed, *C1C2Fixed, params.PRECISIONDECIMALSIZE*2+params.PRECISIONDECIMALSIZEX, params);
//    PrintMatrixDouble(*C0C1C2Fixed);

//    EncodeC1Matrix(cc, C1C2Fixed, C1C2FixedP, primeList, batchSize);
    EncodeC1Matrix(context.cc, numeratorC1C2CRT, C1C2FixedP, primeList, batchSize);

    for(size_t k=0; k<primeList.size(); k++){
    	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C1C2Fixedt = context.cc[k]->EncryptMatrix(context.pk[k], *(C1C2FixedP[k]));
    	C1C2FixedC.push_back(C1C2Fixedt);
    }
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingClient.process[2] = timingClient.process[2] + (finish - start);
#endif

#ifdef MEASURE_TIMING
	start = currentDateTime();
#endif
    for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
    	string BetaPath = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextWFileName+"-" + std::to_string(k) + ".txt";
    	SerializeCiphertext(C1C2FixedC[k], BetaPath);
    }
#ifdef MEASURE_TIMING
    finish = currentDateTime();
    timingClient.write[2] = timingClient.write[2] + (finish - start);
#endif

    return regResultRow;
}

double GLMClientComputeError(GLMContext &context, pathList &path, glmParams & params){

//	vector<CryptoContext<DCRTPoly>> cc;
//	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>>  y;
	vector<shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>>  mu;

//	vector<LPPublicKey<DCRTPoly>> pk;
//	vector<LPPrivateKey<DCRTPoly>> sk;

	for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {
/*
		string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
		string skFileName = path.keyDir+"/"+path.keyfileName+"-private" + std::to_string(k) + ".txt";

		// Deserialize the crypto context
		CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
		cc.push_back(cct);

		cc[k]->Enable(ENCRYPTION);
		cc[k]->Enable(SHE);

		size_t m = cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

		LPPrivateKey<DCRTPoly> skt = DeserializePrivateKey(cc[k], skFileName);
		sk.push_back(skt);

		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+ "-" + path.ciphertextYFileName + "-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yt = DeserializeCiphertext(cc[k], pathToFile);
		y.push_back(yt);
*/
		string pathToFile;
		pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+ "-" + path.ciphertextMUFileName + "-" + std::to_string(k) + ".txt";
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> mut = DeserializeCiphertext(context.cc[k], pathToFile);
		mu.push_back(mut);
	}

	size_t numCol;
    size_t numRow;
    ReadMetaData(path.ciphertextDataDir, path.ciphertextDataFileName, numCol, numRow);

	auto zeroAllocBigInteger = [=]() { return BigInteger(); };
	auto zeroAllocPacking = [=]() { return context.cc[0]->MakePackedPlaintext({0}); };
	size_t dataMatrixRowSize = (*context.y[0]).GetRows();

    vector<Matrix<Plaintext>> yCRT;
    for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {

		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	shared_ptr<Matrix<Plaintext>> numeratory (new Matrix<Plaintext>(zeroAllocPacking, dataMatrixRowSize, 1));
    	context.cc[k]->DecryptMatrixNumerator(context.sk[k], context.y[k], &numeratory);
    	yCRT.push_back(*numeratory);
    }

    vector<Matrix<Plaintext>> muCRT;
    for(size_t k = 0; k < params.PLAINTEXTPRIMESIZE; k++) {

		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	shared_ptr<Matrix<Plaintext>> numeratormu (new Matrix<Plaintext>(zeroAllocPacking, dataMatrixRowSize, 1));
    	context.cc[k]->DecryptMatrixNumerator(context.sk[k], mu[k], &numeratormu);
    	muCRT.push_back(*numeratormu);
    }

    shared_ptr<Matrix<BigInteger>> yBigInt (new Matrix<BigInteger>(zeroAllocBigInteger));
    shared_ptr<Matrix<BigInteger>> muBigInt (new Matrix<BigInteger>(zeroAllocBigInteger));

    (*yBigInt).SetSize(dataMatrixRowSize, context.cc[0]->GetRingDimension() /*params.ENTRYSIZE*/);
    (*muBigInt).SetSize(dataMatrixRowSize, context.cc[0]->GetRingDimension() /*params.ENTRYSIZE*/);

    vector<NativeInteger> primeList;
    for(size_t k=0; k<params.PLAINTEXTPRIMESIZE; k++){
		size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
		EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
		PackedEncoding::SetParams(m, encodingParams);

    	uint64_t prime = context.cc[k]->GetEncodingParams()->GetPlaintextModulus();
    	primeList.push_back(prime);
    }

    size_t colIndex = 0;
    CRTInterpolateMatrixEntrySelect(yCRT, *yBigInt, primeList, colIndex);
    CRTInterpolateMatrixEntrySelect(muCRT, *muBigInt, primeList, colIndex);

    return ComputeError(*yBigInt, *muBigInt, numRow, params);
}

#ifdef MEASURE_TIMING
void GLMPrintTimings(string sel){

	if(sel == "Client"){
		cout << endl;
		cout << "Step 1 - Client" << endl;
		cout << "Read\t" << timingClient.read[0]/1000.0 << endl;
		cout << "Process\t" << timingClient.process[0]/1000.0 << endl;
		cout << "Write\t" << timingClient.write[0]/1000.0 << endl;
		cout << endl;

		cout << endl;
		cout << "Step 2 - Client" << endl;
		cout << "Read\t" << timingClient.read[1]/1000.0 << endl;
		cout << "Process\t" << timingClient.process[1]/1000.0 << endl;
		cout << "Write\t" << timingClient.write[1]/1000.0 << endl;
		cout << endl;

		cout << endl;
		cout << "Step 3 - Client" << endl;
		cout << "Read\t" << timingClient.read[2]/1000.0 << endl;
		cout << "Process\t" << timingClient.process[2]/1000.0 << endl;
		cout << "Write\t" << timingClient.write[2]/1000.0 << endl;
		cout << endl;

	}
	else if(sel == "Server"){
		cout << endl;
		cout << "Step 1 - Server" << endl;
		cout << "Read\t" << timingServer.read[0]/1000.0 << endl;
		cout << "Process\t" << timingServer.process[0]/1000.0 << endl;
		cout << "Write\t" << timingServer.write[0]/1000.0 << endl;
		cout << endl;

		cout << endl;
		cout << "Step 2 - Server" << endl;
		cout << "Read\t" << timingServer.read[1]/1000.0 << endl;
		cout << "Process\t" << timingServer.process[1]/1000.0 << endl;
		cout << "Write\t" << timingServer.write[1]/1000.0 << endl;
		cout << endl;

		cout << endl;
		cout << "Step 3 - Server" << endl;
		cout << "Read\t" << timingServer.read[2]/1000.0 << endl;
		cout << "Process\t" << timingServer.process[2]/1000.0 << endl;
		cout << "Write\t" << timingServer.write[2]/1000.0 << endl;
		cout << endl;
	}
}
#endif

/////////////////////////////////////////////////////////////////////////
/////////                     GENERATORS                        /////////
/////////////////////////////////////////////////////////////////////////

void MessagePrimeListGen(vector<NativeInteger> &primeList, usint &m, glmParams & params){

//	usint m = 65536;//params.CYCLOTOMICM;

	BigInteger modulusP;
	NativeInteger p = FirstPrime<NativeInteger>(params.PLAINTEXTBITSIZE, m);

	modulusP = p;
	primeList.push_back(p);
	for(size_t i=1; i<params.PLAINTEXTPRIMESIZE; i++){
		p = lbcrypto::NextPrime(p, m);
		modulusP = modulusP*p;
		primeList.push_back(p);
	}
}
/*
shared_ptr<ILDCRTParams<BigInteger>> CiphertextDCRTParamGen(NativeInteger &prime, glmParams & params){

	usint m = params.CYCLOTOMICM;

	// populate the towers for the small modulus

	vector<NativeInteger> init_moduli(init_size);
	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, m);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(m, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, m);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(m, init_moduli[i]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity));

	return paramsDCRT;
}
*/
EncodingParams PlaintextEncodingParamGen(NativeInteger &prime, usint &m, glmParams & params){

//	usint m = 65536;//params.CYCLOTOMICM;
	size_t batchSize = m/2;//params.ENTRYSIZE;
	PlaintextModulus modulusP = prime.ConvertToInt();

	EncodingParams encodingParams(new EncodingParamsImpl(modulusP, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);
	encodingParams->SetBatchSize(batchSize);

	return encodingParams;
}

/////////////////////////////////////////////////////////////////////////
/////////                     READ/WRITE                        /////////
/////////////////////////////////////////////////////////////////////////

void ReadCSVFile(string dataFileName, vector<string>& headers, vector<vector<double> >& dataColumns)
{

    ifstream file(dataFileName);
    string line, value;

    uint32_t cols;

    if(file.good()) {
		getline(file, line);
		cols = std::count(line.begin(), line.end(), ',') + 1;
		stringstream ss(line);

		for(uint32_t i = 0; i < cols; i++) {
			string substr;
			getline(ss, substr, ',');
			headers.push_back(substr);
			vector<double> dataCol;
			dataColumns.push_back(dataCol);
		}
    }

    while(file.good()) {
		getline(file, line);
		if(line.find(",") == std::string::npos)
			break;
		stringstream ss(line);
		for(uint32_t i = 0; i < cols; i++) {
			string substr;
			getline(ss, substr, ',');
			double val = std::stod(substr, nullptr);
			dataColumns[i].push_back(val);
		}
    }
}

void ReadMetaData(string ciphertextDataDir, string ciphertextDataFileName, size_t &numCol, size_t &numRow){

	string readFile = ciphertextDataDir + "/lr_data_" + ciphertextDataFileName;
    vector<string> headers;

	ifstream myfile(readFile);
    string value;
    getline(myfile, value);
    uint32_t numHeaders = stoi(value);

    getline(myfile, value, '\n');
    uint32_t numRows = stoi(value);

    while(myfile.good()) {
	getline(
	    myfile, value, '\n'); // read a string until next comma: http://www.cplusplus.com/reference/string/getline/
		headers.push_back(value);
    }
    myfile.close();
    numCol = numHeaders;
    numRow = numRows;
}

void WriteMetaData(const string &metaDataPath, const vector<string> &headers, const vector<vector<double>> &dataColumns){

	uint32_t numHeaders = headers.size();

	ofstream myfile;
    myfile.open(metaDataPath);
    myfile << to_string(numHeaders) + "\n";
    myfile << to_string(dataColumns[0].size());
    for(uint32_t i = 0; i < numHeaders; ++i)
	myfile << "\n" + headers[i];
    myfile.close();

}

void WritePlaintextSpacePrimes(string dataDir, string dataFileName, const vector<NativeInteger> &primeList){
	ofstream myfile;
    myfile.open(dataDir + "/primeList_data_" + dataFileName);
    myfile << to_string(primeList.size());

    for(uint32_t i = 0; i < primeList.size(); ++i)
    	myfile << "\n" + primeList[i].ToString();

    myfile.close();
}

void ReadPlaintextSpacePrimes(string dataDir, string dataFileName, vector<BigInteger> &primeList){
    ifstream file(dataDir + "/primeList_data_" + dataFileName);
    string line, value;

    //get dummy line which gives length info
    getline(file, line);
    while(file.good()) {
    	getline(file, line);

    	BigInteger temp;
		temp.SetValue(line);
		primeList.push_back(temp);
    }
}

void ParseData(vector<vector<double>> &dataColumns, vector<vector<double>> &xPDouble, vector<vector<double>> &yPDouble){

	size_t colSize = dataColumns.size();
	size_t rowSize = dataColumns[0].size();

	for(size_t i=1; i<colSize; i++){
		vector<double> xTemp;

		for(size_t j=0; j<rowSize; j++){
			if(i == 1)
				xTemp.push_back(1);
			else
				xTemp.push_back(dataColumns[i][j]);
		}

		xPDouble.push_back(xTemp);
	}

	vector<double> yTemp;
	for(size_t j=0; j<rowSize; j++){
		yTemp.push_back(dataColumns[1][j]);
	}

	yPDouble.push_back(yTemp);
}

/////////////////////////////////////////////////////////////////////////
/////////                     Deserialize/Serialize             /////////
/////////////////////////////////////////////////////////////////////////

CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName){

	Serialized	ccSer;
	if (SerializableHelper::ReadSerializationFromFile(ccFileName, &ccSer) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(ccSer);
	return cc;
}

LPPublicKey<DCRTPoly> DeserializePublicKey(CryptoContext<DCRTPoly> &cc, const string& pkFileName){

	Serialized pkSer;
	if(SerializableHelper::ReadSerializationFromFile(pkFileName, &pkSer) == false) {
		cerr << "Could not read public key" << endl;
		return 0;
	}

	LPPublicKey<DCRTPoly> pkt = cc->deserializePublicKey(pkSer);

	if(!pkt) {
		cerr << "Could not deserialize public key" << endl;
		return 0;
	}
	return pkt;
}

LPPrivateKey<DCRTPoly> DeserializePrivateKey(CryptoContext<DCRTPoly> &cc, const string& skFileName){

	Serialized skSer;
	if(SerializableHelper::ReadSerializationFromFile(skFileName, &skSer) == false) {
		cerr << "Could not read private key" << endl;
		return 0;
	}

	LPPrivateKey<DCRTPoly> skt = cc->deserializeSecretKey(skSer);

	if(!skt) {
		cerr << "Could not deserialize private key" << endl;
		return 0;
	}
	return skt;
}

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> DeserializeCiphertext(CryptoContext<DCRTPoly> &cc, const string &xFileName){

	auto zeroAllocRationalCiphertext = [=]() { return cc; };
	// Deserialize X
	Serialized xSer;
	if(SerializableHelper::ReadSerializationFromFile(xFileName, &xSer) == false) {
		cerr << "Could not read ciphertext " + xFileName << endl;
		return 0;
	}

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xt(new Matrix<RationalCiphertext<DCRTPoly> >(zeroAllocRationalCiphertext));

	if(!xt->Deserialize(xSer)) {
		cerr << "Could not deserialize ciphertext " + xFileName << endl;
		return 0;
	}
	return xt;
}

void DeserializeEvalMult(CryptoContext<DCRTPoly> &cc, const string& emFileName){

	// Deserialize the eval mult key
	Serialized emSer;
	if(SerializableHelper::ReadSerializationFromFile(emFileName, &emSer) == false) {
		cerr << "Could not read multiplication evaluation key" << endl;
		return;
	}

	if(!cc->DeserializeEvalMultKey(emSer)) {
		cerr << "Could not deserialize multiplication evaluation key" << endl;
		return;
	}
}

void DeserializeEvalSum(CryptoContext<DCRTPoly> &cc, const string& esFileName){
	// Deserialize the eval sum keys
	Serialized esSer;
	if(SerializableHelper::ReadSerializationFromFile(esFileName, &esSer) == false) {
		cerr << "Could not read the sum evaluation key " << endl;
		return;
	}

	if(!cc->DeserializeEvalSumKey(esSer)) {
		cerr << "Could not deserialize summation evaluation key" << endl;
		return;
	}
}

void SerializeContext(CryptoContext<DCRTPoly> &cc, const string &xFileName){
	Serialized ctxt;
	if(cc->Serialize(&ctxt)) {
		if(!SerializableHelper::WriteSerializationToFile(ctxt, xFileName)) {
		cerr << "Error writing serialization of the crypto context to cryptotext" + xFileName << endl;
		return;
	    }
	}
	else {
		cerr << "Error serializing the crypto context" << endl;
	    return;
	}
}

void SerializePublicKey(LPPublicKey<DCRTPoly> &kp, const string &xFileName){
	Serialized pubK;
    if(kp){
    	if(kp->Serialize(&pubK)) {
    		if(!SerializableHelper::WriteSerializationToFile(pubK, xFileName)) {
    			cerr << "Error writing serialization of public key to " << xFileName << endl;
    		return;
    		}
    	}
    	else {
    		cerr << "Error serializing public key" << endl;
    		return;
    	}
    }
    else
    	cerr << "Failure in generating public keys" << endl;

}

void SerializePrivateKey(LPPrivateKey<DCRTPoly> &kp, const string &xFileName){
	Serialized privK;
    if(kp){
    	if(kp->Serialize(&privK)) {
    		if(!SerializableHelper::WriteSerializationToFile(privK, xFileName)) {
    			cerr << "Error writing serialization of private key to key-private" + xFileName << endl;
				    return;
				}
	    }
    	else {
    		cerr << "Error serializing private key" << endl;
    		return;
    	}
    }
    else{
	    	cerr << "Failure in generating private keys" << endl;
    }
}

void SerializeCiphertext(shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C, const string &xFileName){
	Serialized ctxtSer;
	ctxtSer.SetObject();
	if(C->Serialize(&ctxtSer)) {
		if(!SerializableHelper::WriteSerializationToFile(ctxtSer, xFileName)) {
		cerr << "Error writing serialization of ciphertext to "
			 << xFileName << endl;
		return;
		}
	} else {
		cerr << "Error serializing ciphertext " << endl;
		return;
	}
}



void SerializeMultEvalKey(CryptoContext<DCRTPoly> &cc, const vector<LPEvalKey<DCRTPoly>> &evalMultKey, const string &xFileName){

	if(evalMultKey[0]) {
		Serialized evalKey;

		if(cc->SerializeEvalMultKey(&evalKey)) {
		if(!SerializableHelper::WriteSerializationToFile(evalKey, xFileName)) {
			cerr << "Error writing serialization of multiplication evaluation key to key-eval-mult" + xFileName << endl;
			return;
		}
		} else {
		cerr << "Error serializing multiplication evaluation key" << endl;
		return;
		}

	} else {
		cerr << "Failure in generating multiplication evaluation key" << endl;
	}
}

void SerializeSumEvalKey(CryptoContext<DCRTPoly> &cc, const std::map<usint, LPEvalKey<DCRTPoly>>& evalSumKey, const string &xFileName){

	if(evalSumKey.begin()->second) {
		Serialized evalKey;

		if(cc->SerializeEvalSumKey(&evalKey)) {
			if(!SerializableHelper::WriteSerializationToFile(evalKey, xFileName)) {
				cerr << "Error writing serialization of multiplication evaluation key to key-eval-sum" + xFileName << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing summation evaluation key" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating summation evaluation key" << endl;
	}

}

/////////////////////////////////////////////////////////////////////////
/////////                     Arithmetic Functions              /////////
/////////////////////////////////////////////////////////////////////////
double ComputeError(Matrix<BigInteger> &mu, Matrix<BigInteger> &y, size_t size, glmParams &params){

	size_t counter = 0;
	double errorTotal = 0;
	double tempValue;
	for(size_t i=0; i<mu.GetRows(); i++){
		for(size_t j=0; j<mu.GetCols(); j++){

			double muValue = mu(i,j).ConvertToDouble();
			DecimalDecrement(muValue, muValue, params.PRECISIONDECIMALSIZE, params);
			double yValue =  y(i,j).ConvertToDouble();
			DecimalDecrement(yValue, yValue, params.PRECISIONDECIMALSIZE, params);

			tempValue = (muValue-yValue);
			errorTotal = errorTotal + tempValue*tempValue;

			counter++;
			if(size == counter)
				return sqrt(errorTotal/size);
		}
	}
	return sqrt(errorTotal/size);
}

void LinkFunctionLogisticSigned(vector<CryptoContext<DCRTPoly>> &cc,
								const Matrix<BigInteger> &wTb,
								vector<shared_ptr<Matrix<Plaintext>>> &mu,
								vector<shared_ptr<Matrix<Plaintext>>> &S,
								const size_t dataEntrySize,
								const vector<NativeInteger> &primeList,
								string regAlgorithm,
								glmParams &params){

	vector<double> meanList;
	vector<double> weightList;
	double yTilde, mean, weight;
	uint64_t meanFloor, weightFloor;
	BigInteger Q, q, temp;

	q.SetValue(primeList[0].ToString());
	Q.SetValue(primeList[0].ToString());
	for(size_t k=1; k<primeList.size(); k++){
		q.SetValue(primeList[k].ToString());
		Q = Q*q;
	}

	auto zeroPackingAlloc = [=]() { return cc[0]->MakePackedPlaintext({0}); };
	for(size_t k=0; k<primeList.size(); k++){
		shared_ptr<Matrix<Plaintext>> mut(new Matrix<Plaintext>(zeroPackingAlloc, wTb.GetRows(), 1));
		mu.push_back(mut);

		shared_ptr<Matrix<Plaintext>> St(new Matrix<Plaintext>(zeroPackingAlloc, wTb.GetRows(), 1));
		S.push_back(St);
	}

	double start, finish;

	start = currentDateTime();

	size_t counter = 0;
	bool isSizeMax = false;
	for(size_t j=0; (j<wTb.GetRows()) && !isSizeMax; j++){
		for(size_t i=0; (i<wTb.GetCols()) && !isSizeMax; i++){
			BigInteger q2 = Q>>1;
			if(wTb(j, i)>q2)
				yTilde = (Q-wTb(j, i)).ConvertToDouble()*(-1);
			else
				yTilde = wTb(j, i).ConvertToDouble();

			//Rescale computed y to normal
			DecimalDecrement(yTilde, yTilde, 2*params.PRECISIONDECIMALSIZE+2*params.PRECISIONDECIMALSIZEX, params);

			if(regAlgorithm == "NORMAL"){
				//Mean for Logistic Function
				mean = yTilde;
				//Weight function
				weight = 1.0;
			}
			else if(regAlgorithm == "LOGISTIC"){
				//Mean for Logistic Function
				mean = 1.0/(1.0+exp(-yTilde));
				//Weight function
				weight = mean*(1.0-mean);
			}
			else if(regAlgorithm == "POISSON"){
				//Mean for Logistic Function
				mean = exp(yTilde);
				//Weight function
				weight = mean;
			}
			else{

				mean = 0;
				//Weight function
				weight = 0;
			}
			meanList.push_back(mean);
			weightList.push_back(weight);

			counter++;
			if(dataEntrySize == counter)
				isSizeMax = true;
		}
	}

	finish = currentDateTime();
	cout << "Link-1\t" << finish-start << endl;

	start = currentDateTime();
	size_t entrySizeForRow;
	size_t entrySize = meanList.size();
	size_t matrixRowSize = entrySize/cc[0]->GetRingDimension(); //params.ENTRYSIZE;

	if((entrySize%cc[0]->GetRingDimension() /*params.ENTRYSIZE*/) != 0)
		matrixRowSize++;

	double meanScaled, weightScaled;
	for(size_t k=0; k<primeList.size(); k++){

		q.SetValue(primeList[k].ToString());

		size_t matrixRowIndex = 0;
		for(size_t l = 0; l < matrixRowSize; l++) {
			vector<uint64_t> vectorOfMu, vectorOfS;

			if(l == matrixRowSize-1){
				if((entrySize%cc[0]->GetRingDimension()/*params.ENTRYSIZE*/) != 0)
					entrySizeForRow = entrySize%cc[0]->GetRingDimension()/*params.ENTRYSIZE*/;
				else
					entrySizeForRow = cc[0]->GetRingDimension()/*params.ENTRYSIZE*/;
			}
			else
				entrySizeForRow = cc[0]->GetRingDimension()/*params.ENTRYSIZE*/;

			for(size_t j = 0; j < entrySizeForRow; j++){

				DecimalIncrement(meanList[matrixRowIndex], meanScaled, params.PRECISIONDECIMALSIZE, params);
				meanFloor = floor(meanScaled);
				temp = (BigInteger(meanFloor)).Mod(q);
				vectorOfMu.push_back(temp.ConvertToInt());

				DecimalIncrement(weightList[matrixRowIndex], weightScaled, params.PRECISIONDECIMALSIZE, params);
				weightFloor = floor(weightScaled);
				temp = (BigInteger(weightFloor)).Mod(q);
				vectorOfS.push_back(temp.ConvertToInt());

				matrixRowIndex++;
			}

			(*(mu[k]))(l, 0) = cc[k]->MakePackedPlaintext(vectorOfMu);
			(*(S[k]))(l, 0) = cc[k]->MakePackedPlaintext(vectorOfS);
		}
	}

	finish = currentDateTime();
	cout << "Link-1\t" << finish-start << endl;

}

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyWTransX(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &beta){

	auto zeroAllocPacking = [=]() { return cc->MakePackedPlaintext({0}); };
	auto zeroAllocRationalCiphertext = [=]() { return cc; };

	size_t dataMatrixRowSize = (*x).GetRows();
	size_t numRegressors = (*x).GetCols();

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> result(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, dataMatrixRowSize, 1));
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTbt(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, dataMatrixRowSize, numRegressors));

	const Ciphertext<DCRTPoly> xi = (*x)(0, 0).GetNumerator();
	const Ciphertext<DCRTPoly> bk = (*beta)(0, 0).GetNumerator();
	Ciphertext<DCRTPoly> t = cc->EvalMult(xi, bk);

	((*xTbt)(0, 0)).SetNumerator(t);


//#pragma omp parallel for shared(beta, x, xTbt, dataMatrixRowSize, numRegressors, cc) default(shared) num_threads(8) collapse(2)
#pragma omp parallel for shared(cc, x, beta, xTbt, dataMatrixRowSize, numRegressors) num_threads(8) collapse(2)
	for(size_t row=0; row<dataMatrixRowSize; row++){
		for(size_t col = 0; col < numRegressors; col++) {

			const Ciphertext<DCRTPoly> xi = (*x)(row, col).GetNumerator();
			const Ciphertext<DCRTPoly> bk = (*beta)(0, col).GetNumerator();
			Ciphertext<DCRTPoly> t = cc->EvalMult(xi, bk);

			((*xTbt)(row, col)).SetNumerator(t);
		}
	}

#pragma omp parallel for shared(cc, result, xTbt, dataMatrixRowSize, numRegressors) num_threads(8)
	for(size_t row=0; row<dataMatrixRowSize; row++){

		Ciphertext<DCRTPoly> tempSum(new CiphertextImpl<DCRTPoly>(cc));
		tempSum = ((*xTbt)(row, 0)).GetNumerator();

		for(size_t col = 1; col < numRegressors; col++) {

			const Ciphertext<DCRTPoly> tm = ((*xTbt)(row, col)).GetNumerator();
			tempSum = cc->EvalAdd(tempSum, tm);
		}
		((*result )(row, 0)).SetNumerator(tempSum);
	}

	return result;

}

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXTransX(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x){

	auto zeroAllocPacking = [=]() { return cc->MakePackedPlaintext({0}); };
	auto zeroAllocRationalCiphertext = [=]() { return cc; };

	size_t rowSize = (*x).GetRows();
	size_t colSize = (*x).GetCols();

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTbt(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, rowSize, colSize));
	Ciphertext<DCRTPoly> result(new CiphertextImpl<DCRTPoly>(cc));

	#ifdef OMPSECTION1
	#pragma omp parallel for num_threads(NUMTHREADS)
	#endif
	for(size_t row=0; row<rowSize; row++){
		for(size_t col = 0; col < colSize; col++) {
			const Ciphertext<DCRTPoly> xi = (*x)(row, col).GetNumerator();
			Ciphertext<DCRTPoly> t = cc->EvalMult(xi, xi);
			((*xTbt)(row, col)).SetNumerator(t);
		}
	}
	return xTbt;
}

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXTransS(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &SC){

	size_t dataMatrixRowSize = (*x).GetRows();
	size_t numRegressors = (*x).GetCols();
	auto zeroAllocRationalCiphertext = [=]() { return cc; };

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTSt(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, dataMatrixRowSize, numRegressors));
	#ifdef OMPSECTION3
//	#pragma omp parallel for shared(x, SC, xTSt, numRegressors, cc) default(shared) num_threads(NUMTHREADS)
	#pragma omp parallel for num_threads(NUMTHREAD)
	#endif

	Ciphertext<DCRTPoly> xi = (*x)(0, 0).GetNumerator();
	Ciphertext<DCRTPoly> si = (*SC)(0,0).GetNumerator();

	Ciphertext<DCRTPoly> result = cc->EvalMult(xi, si);

//#pragma omp parallel for shared(x, SC, xTSt, dataMatrixRowSize, numRegressors) num_threads(8) collapse(2)

#pragma omp parallel for shared(cc, x, SC, xTSt, dataMatrixRowSize, numRegressors) num_threads(8) collapse(2)
	for(size_t row = 0; row < dataMatrixRowSize; row++) {
		for(size_t col = 0; col < numRegressors; col++) {
//			if(row!=0 && col!=0){
				Ciphertext<DCRTPoly> xi = (*x)(row, col).GetNumerator();
				Ciphertext<DCRTPoly> si = (*SC)(row,0).GetNumerator();

				Ciphertext<DCRTPoly> result = cc->EvalMult(xi, si);

				(*xTSt)(row, col).SetNumerator(result);
			}
		}
//	}

	return xTSt;
}
/*
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXTransSX(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C0){

	size_t dataMatrixRowSize = (*x).GetRows();
	size_t numRegressors = (*x).GetCols();
	auto zeroAllocRationalCiphertext = [=]() { return cc; };

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTSxt(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, numRegressors, numRegressors));
#ifdef OMPSECTION3
//#pragma omp parallel for shared(xTSt, x, xTSxt, k, numRegressors, cc) default(shared) num_threads(NUMTHREADS) collapse(2)
#pragma omp parallel for num_threads(NUMTHREAD) collapse(2)
#endif

	Ciphertext<DCRTPoly> result(new CiphertextImpl<DCRTPoly>(cc));
	for(size_t row = 0; row < 1; row++){
		const Ciphertext<DCRTPoly> xTSk = (*C0)(0, 0).GetNumerator();
		const Ciphertext<DCRTPoly> xk   = (*x)(0, 0).GetNumerator();

		Ciphertext<DCRTPoly> temp = cc->EvalMult(xTSk, xk);

		if(row == 0)
			result = temp;
		else
			result = cc->EvalAdd(result, temp);
	}
	(*xTSxt)(0, 0).SetNumerator(result);

#pragma omp parallel for shared(cc, C0, x, xTSxt, dataMatrixRowSize, numRegressors) num_threads(8) collapse(2)
	for(size_t col1 = 0; col1 < numRegressors; col1++) {
		for(size_t col2 = 0; col2 < numRegressors; col2++){

			Ciphertext<DCRTPoly> result(new CiphertextImpl<DCRTPoly>(cc));
			for(size_t row = 0; row < dataMatrixRowSize; row++){
				const Ciphertext<DCRTPoly> xTSk = (*C0)(row, col1).GetNumerator();
				const Ciphertext<DCRTPoly> xk   = (*x)(row, col2).GetNumerator();

				Ciphertext<DCRTPoly> temp = cc->EvalMult(xTSk, xk);

				if(row == 0)
					result = temp;
				else
					result = cc->EvalAdd(result, temp);
			}
			(*xTSxt)(col1, col2).SetNumerator(result);
		}
	}

#pragma omp parallel for shared(cc, x, xTSxt, numRegressors) num_threads(8) collapse(2)
	for(size_t col1 = 0; col1 < numRegressors; col1++) {
		for(size_t col2 = 0; col2 < numRegressors; col2++){
			Ciphertext<DCRTPoly> t = (*xTSxt)(col1, col2).GetNumerator();
			t = cc->EvalSum(t, cc->GetEncodingParams()->GetBatchSize());
			(*xTSxt)(col1, col2).SetNumerator(t);
		}
	}

	return xTSxt;
}
*/
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXTransSX(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C0){

	size_t dataMatrixRowSize = (*x).GetRows();
	size_t numRegressors = (*x).GetCols();
	auto zeroAllocRationalCiphertext = [=]() { return cc; };

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTSxt(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, numRegressors, numRegressors));
#ifdef OMPSECTION3
//#pragma omp parallel for shared(xTSt, x, xTSxt, k, numRegressors, cc) default(shared) num_threads(NUMTHREADS) collapse(2)
#pragma omp parallel for num_threads(NUMTHREAD) collapse(2)
#endif

//	Ciphertext<DCRTPoly> result(new CiphertextImpl<DCRTPoly>(cc));
//	for(size_t row = 0; row < 1; row++){
		const Ciphertext<DCRTPoly> xTSk = (*C0)(0, 0).GetNumerator();
		const Ciphertext<DCRTPoly> xk   = (*x)(0, 0).GetNumerator();

		Ciphertext<DCRTPoly> result = cc->EvalMult(xTSk, xk);

//		if(row == 0)
//			result = temp;
//		else
//			result = cc->EvalAdd(result, temp);
//	}
	(*xTSxt)(0, 0).SetNumerator(result);


	vector<size_t> cordX;
	vector<size_t> cordY;

	for(size_t col1 = 0; col1 < numRegressors; col1++) {
		for(size_t col2 = 0; col2 <= col1; col2++){
			cordX.push_back(col1);
			cordY.push_back(col2);
		}
	}

//	size_t loopCount = (numRegressors*numRegressors-numRegressors)/2;

#pragma omp parallel for shared(cc, C0, x, xTSxt, dataMatrixRowSize, cordX, cordY) schedule(dynamic) num_threads(8)
	for(size_t loop=0; loop<cordX.size(); loop++){

			Ciphertext<DCRTPoly> result(new CiphertextImpl<DCRTPoly>(cc));
			for(size_t row = 0; row < dataMatrixRowSize; row++){
				const Ciphertext<DCRTPoly> xTSk = (*C0)(row, cordX[loop]).GetNumerator();
				const Ciphertext<DCRTPoly> xk   = (*x)(row, cordY[loop]).GetNumerator();

				Ciphertext<DCRTPoly> temp = cc->EvalMult(xTSk, xk);

				if(row == 0)
					result = temp;
				else
					result = cc->EvalAdd(result, temp);
			}
			(*xTSxt)(cordX[loop], cordY[loop]).SetNumerator(result);
	}

#pragma omp parallel for shared(cc, x, xTSxt, cordX, cordY) schedule(dynamic) num_threads(8)
	for(size_t loop=0; loop<cordX.size(); loop++){
			Ciphertext<DCRTPoly> t = (*xTSxt)(cordX[loop], cordY[loop]).GetNumerator();
			t = cc->EvalSum(t, cc->GetEncodingParams()->GetBatchSize());
			(*xTSxt)(cordX[loop], cordY[loop]).SetNumerator(t);
	}


	for(size_t col1 = 0; col1 < numRegressors; col1++) {
		for(size_t col2 = 0; col2 < col1; col2++){
			(*xTSxt)(col2, col1).SetNumerator((*xTSxt)(col1, col2).GetNumerator());
		}
	}



	return xTSxt;
}

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXAddYMu(CryptoContext<DCRTPoly> &cc,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &y,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &muC){

	auto zeroAllocRationalCiphertext = [=]() { return cc; };
	size_t dataMatrixRowSize = (*x).GetRows();
	size_t dataMatrixColSize = (*x).GetCols();

	Ciphertext<DCRTPoly> xwSyMu(new CiphertextImpl<DCRTPoly>(cc));
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yMu = cc->EvalSubMatrix(y, muC);
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C2t(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, 1, dataMatrixColSize));

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C2mid(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, dataMatrixRowSize, dataMatrixColSize));

	const Ciphertext<DCRTPoly> c1 = (*x)(0, 0).GetNumerator();
	const Ciphertext<DCRTPoly> c2 = (*yMu)(0, 0).GetNumerator();

	const Ciphertext<DCRTPoly> t = cc->EvalMult(c1, c2);

	(*C2mid)(0, 0).SetNumerator(t);

#pragma omp parallel for shared(cc, x, yMu, C2mid, dataMatrixRowSize, dataMatrixColSize) num_threads(8) collapse(2)
	for(size_t colIndex=0; colIndex<dataMatrixColSize; colIndex++){
		for(size_t rowIndex=0; rowIndex<dataMatrixRowSize; rowIndex++){

			const Ciphertext<DCRTPoly> c1 = (*x)(rowIndex, colIndex).GetNumerator();
			const Ciphertext<DCRTPoly> c2 = (*yMu)(rowIndex, 0).GetNumerator();

			const Ciphertext<DCRTPoly> t = cc->EvalMult(c1, c2);

			(*C2mid)(rowIndex, colIndex).SetNumerator(t);
		}
	}

#pragma omp parallel for shared(cc, C2t, C2mid, dataMatrixColSize, dataMatrixRowSize) num_threads(8)
	for(size_t colIndex=0; colIndex<dataMatrixColSize; colIndex++){

		Ciphertext<DCRTPoly> result = (*C2mid)(0, colIndex).GetNumerator();

		for(size_t rowIndex=1; rowIndex<dataMatrixRowSize; rowIndex++){

			const Ciphertext<DCRTPoly> t = (*C2mid)(rowIndex, colIndex).GetNumerator();
			result = cc->EvalAdd(result, t);
		}
		(*C2t)(0, colIndex).SetNumerator(result);
	}

#pragma omp parallel for shared(cc, C2t, dataMatrixColSize) num_threads(8)
	for(size_t colIndex=0; colIndex<dataMatrixColSize; colIndex++){

		Ciphertext<DCRTPoly> t = (*C2t)(0, colIndex).GetNumerator();
		t = cc->EvalSum(t, cc->GetEncodingParams()->GetBatchSize());
		(*C2t)(0, colIndex).SetNumerator(t);
	}

	return C2t;
}

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyC1C2(CryptoContext<DCRTPoly> &cc,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C1,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C2){

	auto zeroAllocRationalCiphertext = [=]() { return cc; };
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C1C2t(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, 1, (*C1).GetCols()));
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C1C2mid(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, (*C1).GetRows(), (*C1).GetCols()));

	const Ciphertext<DCRTPoly> c1 = (*C1)(0, 0).GetNumerator();
	const Ciphertext<DCRTPoly> c2 = (*C2)(0, 0).GetNumerator();

	const Ciphertext<DCRTPoly> t = cc->EvalMult(c1, c2);

	(*C1C2mid)(0, 0).SetNumerator(t);

#pragma omp parallel for shared(cc, C1, C2, C1C2mid) num_threads(8) collapse(2)
	for(size_t colIndex=0; colIndex<(*C1).GetCols(); colIndex++){
		for(size_t rowIndex=0; rowIndex<(*C1).GetRows(); rowIndex++){

			const Ciphertext<DCRTPoly> c1 = (*C1)(colIndex, rowIndex).GetNumerator();
			const Ciphertext<DCRTPoly> c2 = (*C2)(0, rowIndex).GetNumerator();

			const Ciphertext<DCRTPoly> t = cc->EvalMult(c1, c2);

			(*C1C2mid)(colIndex, rowIndex).SetNumerator(t);
		}
	}

#pragma omp parallel for shared(cc, C1, C1C2mid, C1C2t) num_threads(8)
	for(size_t colIndex=0; colIndex<(*C1).GetCols(); colIndex++){

		Ciphertext<DCRTPoly> result = (*C1C2mid)(colIndex, 0).GetNumerator();

		for(size_t rowIndex=1; rowIndex<(*C1).GetRows(); rowIndex++){
			const Ciphertext<DCRTPoly> t = (*C1C2mid)(colIndex, rowIndex).GetNumerator();
			result = cc->EvalAdd(result, t);
		}
		(*C1C2t)(0, colIndex).SetNumerator(result);
	}

	return C1C2t;
}

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyC0C1(CryptoContext<DCRTPoly> &cc,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C0,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C1){

	size_t dataMatrixRowSize = (*C0).GetRows();
	size_t numRegressors = (*C0).GetCols();

	auto zeroAllocRationalCiphertext = [=]() { return cc; };
    shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C0C1t(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, dataMatrixRowSize, numRegressors));

	for(size_t row=0; row<dataMatrixRowSize; row++){
		for(size_t col=0; col<numRegressors; col++){

			size_t col2=0;
			Ciphertext<DCRTPoly> result(new CiphertextImpl<DCRTPoly>(cc));

			Ciphertext<DCRTPoly> t = cc->EvalMult((*(C0))(row, col2).GetNumerator(), (*(C1))(col, col2).GetNumerator() );
			result = t;

			for(size_t col2=1; col2<numRegressors; col2++){
				Ciphertext<DCRTPoly> t = cc->EvalMult((*(C0))(row, col2).GetNumerator(), (*(C1))(col, col2).GetNumerator() );
				result = cc->EvalAdd(result, t);
			}
			(*C0C1t)(row, col).SetNumerator(result);
		}
	}
	return C0C1t;
}

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyC0C1C2(CryptoContext<DCRTPoly> &cc,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C0C1,
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C2){

	size_t dataMatrixRowSize = (*C0C1).GetRows();
	size_t numRegressors = (*C0C1).GetCols();
	auto zeroAllocRationalCiphertext = [=]() { return cc; };
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> C0C1C2t(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAllocRationalCiphertext, 1, numRegressors));

	for(size_t col=0; col<numRegressors; col++){
		Ciphertext<DCRTPoly> result;
		for(size_t row=0; row<dataMatrixRowSize; row++){
			const Ciphertext<DCRTPoly> c1 = (*C0C1)(row, col).GetNumerator();
			const Ciphertext<DCRTPoly> c2 = (*C2)(row, 0).GetNumerator();

			const Ciphertext<DCRTPoly> t = cc->EvalMult(c1, c2);
			if(row == 0)
				result = t;
			else
				result = cc->EvalAdd(result, t);
		}
		(*C0C1C2t)(0, col).SetNumerator(result);
	}

	for(size_t col=0; col<numRegressors; col++){

		Ciphertext<DCRTPoly> t = (*C0C1C2t)(0, col).GetNumerator();
		t = cc->EvalSum(t, cc->GetEncodingParams()->GetBatchSize());
		(*C0C1C2t)(0, col).SetNumerator(t);
	}

	return C0C1C2t;
}

/////////////////////////////////////////////////////////////////////////
/////////                     CRT/Encoding Functions            /////////
/////////////////////////////////////////////////////////////////////////

void CRTInterpolateMatrix(const vector<Matrix<Plaintext>> &crtVector, Matrix<BigInteger> &result, const vector<NativeInteger> &primeList, glmParams &params) {

   	BigInteger Q(1);
   	BigInteger temp;
   	vector<BigInteger> q;

   	for(size_t i=0; i<primeList.size(); i++){
   		temp.SetValue(primeList[i].ToString());
   		q.push_back(temp);
   		Q = Q*temp;
   	}

	std::vector<BigInteger> qInverse;

	for (size_t i = 0; i < crtVector.size(); i++)
		qInverse.push_back((Q/q[i]).ModInverse(q[i]));

	size_t matrixRowIndex, messageIndex;
	for (size_t rowIndex = 0; rowIndex < result.GetRows(); rowIndex++){
		for (size_t colIndex = 0; colIndex < result.GetCols(); colIndex++){

			matrixRowIndex = rowIndex/crtVector[0](0, 0)->GetElementRingDimension() /*params.ENTRYSIZE*/;
			messageIndex   = rowIndex%crtVector[0](0, 0)->GetElementRingDimension() /*params.ENTRYSIZE*/;
			BigInteger value = 0;
			for (size_t i = 0; i < primeList.size(); i++)
				value += ((BigInteger(crtVector[i](matrixRowIndex, colIndex)->GetPackedValue()[messageIndex])*qInverse[i]).Mod(q[i])*(Q/q[i])).Mod(Q);

			value = value.Mod(Q);
			result(rowIndex, colIndex).SetValue(value.ToString());
		}
	}
}

void CRTInterpolateMatrixEntrySelect(const vector<Matrix<Plaintext>> &crtVector, Matrix<BigInteger> &result, const vector<NativeInteger> &primeList, const size_t &colIndex) {
	double start, finish;
start = currentDateTime();
   	BigInteger Q(1);
   	BigInteger temp;
   	vector<BigInteger> q;

   	for(size_t i=0; i<primeList.size(); i++){
   		temp.SetValue(primeList[i].ToString());
   		q.push_back(temp);
   		Q = Q*temp;
   	}

	std::vector<BigInteger> qInverse;

	for (size_t i = 0; i < crtVector.size(); i++)
		qInverse.push_back((Q/q[i]).ModInverse(q[i]));

	std::vector<BigInteger> qI;
	for (size_t i = 0; i < crtVector.size(); i++)
		qI.push_back((Q/q[i]));


finish = currentDateTime();
cout << "Setup\t" << finish-start << endl;

start = currentDateTime();

#pragma omp parallel for shared(result, primeList, colIndex, qInverse, q, Q, qI) num_threads(8) collapse(2)
	for (size_t k = 0; k < result.GetRows(); k++){
		for (size_t j = 0; j < result.GetCols(); j++){
			BigInteger value = 0;

			for (size_t i = 0; i < primeList.size(); i++)
				value += ((BigInteger(crtVector[i](k, colIndex)->GetPackedValue()[j])*qInverse[i]).Mod(q[i])*(qI[i]));//.Mod(Q);

			value = value.Mod(Q);
			result(k, j) = (value);

		}
	}
	finish = currentDateTime();
	cout << "CRTInter\t" << finish-start << endl;

}

void CRTInterpolate(const std::vector<Matrix<Plaintext>> &crtVector, Matrix<BigInteger> &result, const vector<NativeInteger> &primeList) {

   	BigInteger Q(1);
   	BigInteger temp;
   	vector<BigInteger> q;

   	for(size_t i=0; i<primeList.size(); i++){
   		temp.SetValue(primeList[i].ToString());
   		q.push_back(temp);
   		Q = Q*temp;
   	}

	std::vector<BigInteger> qInverse;

	for (size_t i = 0; i < crtVector.size(); i++)
		qInverse.push_back((Q/q[i]).ModInverse(q[i]));

	std::vector<BigInteger> qI;
	for (size_t i = 0; i < crtVector.size(); i++)
		qI.push_back((Q/q[i]));

#pragma omp parallel for shared(result, primeList, crtVector, qInverse, q, Q, qI) num_threads(8) collapse(2)
	for (size_t k = 0; k < result.GetRows(); k++)
	{
		for (size_t j = 0; j < result.GetCols(); j++)
		{
			BigInteger value = 0;
			for (size_t i = 0; i < crtVector.size(); i++)
				value += ((BigInteger(crtVector[i](k,j)->GetPackedValue()[0])*qInverse[i]).Mod(q[i])*(qI[i])); //.Mod(Q);

			value = value.Mod(Q);
			result(k, j) = value; //SetValue(value.ToString());
		}
	}

}

void DiagMatrixInverse(const vector<double> &in, vector<double> &out){

    for(size_t i = 0; i < in.size(); i++)
    	if(in[i] != 0.0)
    		out[i] = 1/in[i];
    	else
    		out[i] = 0.0;
}

void ConvertUnsingedToSigned(const Matrix<BigInteger> &in, Matrix<double> &out, vector<NativeInteger> &primeList){

	BigInteger Q, q;

	q.SetValue(primeList[0].ToString());
	Q.SetValue(primeList[0].ToString());
	for(size_t k=1; k<primeList.size(); k++){
		q.SetValue(primeList[k].ToString());
		Q = Q*q;
	}

	double temp;
	for(size_t i=0; i<in.GetRows(); i++){
		for(size_t j=0; j<in.GetCols(); j++){
			BigInteger q2 = Q>>1;
			if(in(i, j) > q2)
				temp = (Q-in(i, j)).ConvertToDouble()*(-1);
			else
				temp = in(i, j).ConvertToDouble();

			out(i, j) = temp;
		}
	}

}

void MatrixInverse(const Matrix<BigInteger> &in, Matrix<double> &out){

    matrix<double> M(in.GetCols(), in.GetRows());

    for(int i = 0; i < M.getactualsize(); i++)
	for(int j = 0; j < M.getactualsize(); j++)
	    M.setvalue(i, j, in(i, j).ConvertToDouble());

    M.invert();

    out.SetSize(in.GetRows(), in.GetCols());

    bool flag;

    for(int i = 0; i < M.getactualsize(); i++)
	for(int j = 0; j < M.getactualsize(); j++)
	    M.getvalue(i, j, out(i, j), flag);
}

void MatrixInverse(const Matrix<double> &in, Matrix<double> &out){

    matrix<double> M(in.GetCols(), in.GetRows());

    for(int i = 0; i < M.getactualsize(); i++)
	for(int j = 0; j < M.getactualsize(); j++)
	    M.setvalue(i, j, in(i, j));

    M.invert();

    out.SetSize(in.GetRows(), in.GetCols());

    bool flag;

    for(int i = 0; i < M.getactualsize(); i++)
	for(int j = 0; j < M.getactualsize(); j++)
	    M.getvalue(i, j, out(i, j), flag);
}

void ConvertMatrixBigIntegerToPlaintextEncoding(const CryptoContext<DCRTPoly> &cc, const Matrix<BigInteger> &inMat, Matrix<Plaintext> &outMat){

	size_t batchSize = outMat(0, 0)->GetEncodingParams()->GetBatchSize();

	for(size_t j = 0; j < outMat.GetCols(); j++){

		size_t rowIndex = 0;
		for(size_t i = 0; i < outMat.GetRows(); i++){

			vector<uint64_t> vectorOfX;
			for(size_t k=0; k<batchSize; k++){

				vectorOfX.push_back(inMat(rowIndex, j).ConvertToDouble());
				rowIndex++;

				if(rowIndex == inMat.GetRows())
					break;
			}

			outMat(i, j) =  cc->MakePackedPlaintext(vectorOfX);
		}
	}
}

void ConvertPlaintextEncodingToMatrixBigInteger(const CryptoContext<DCRTPoly> &cc, const Matrix<Plaintext> &inMat, Matrix<BigInteger> &outMat, glmParams &params){

	size_t colSize = outMat.GetCols();
	size_t rowSize = outMat.GetRows();

	for(size_t i=0; i<colSize; i++){
		for(size_t j=0; j<rowSize; j++){

			size_t packIndex = j%cc->GetRingDimension(); //params.ENTRYSIZE;
			size_t rowIndex  = j/cc->GetRingDimension(); //params.ENTRYSIZE;

			outMat(j, i) = (inMat(rowIndex, i)->GetPackedValue()[packIndex]);
		}
	}
}

void DataToCRT(vector<vector<double>> &xPVecDouble, vector<Matrix<BigInteger>> &xPMatVec, vector<BigInteger> &primeList, uint64_t &decimalInc, glmParams &params){

    auto zeroAllocDouble = [=]() { return double(); };
    auto zeroAllocBigInteger = [=]() { return BigInteger(); };

    uint64_t dec = params.PRECISION;
    DecimalEncoding de(primeList, dec);

    size_t colSize = xPVecDouble.size();
    size_t rowSize = xPVecDouble[0].size();

    Matrix<double> xPMatDouble = Matrix<double>(zeroAllocDouble, rowSize, colSize);
    Matrix<BigInteger> xPMatBigInteger = Matrix<BigInteger>(zeroAllocBigInteger, rowSize, colSize);

    for(size_t i=0; i<primeList.size(); i++){

        Matrix<BigInteger> xPTemp = Matrix<BigInteger>(zeroAllocBigInteger, rowSize, colSize);
        xPMatVec.push_back(xPTemp);
    }

    de.ConvertVectorToMatrix(xPVecDouble, xPMatDouble);
    de.DecimalIncrement(xPMatDouble, xPMatDouble, decimalInc);
    de.ConvertToBigInteger(xPMatDouble, xPMatBigInteger);
    de.CRT(xPMatBigInteger, xPMatVec);
}

void EncodeData(CryptoContext<DCRTPoly> &cc, const vector<vector<double> >& dataColumns, Matrix<Plaintext>& x, Matrix<Plaintext>& y, glmParams &params){    // columns

	size_t entrySizeForRow;
	size_t entrySize = dataColumns[0].size();
	size_t matrixRowSize = entrySize/cc->GetRingDimension(); //params.ENTRYSIZE;

	if((entrySize%cc->GetRingDimension() /*params.ENTRYSIZE*/) != 0)
		matrixRowSize++;

    for(size_t i = 0; i < 1; i++) {
	// rows
		for(size_t k = 0; k < matrixRowSize; k++) {
			vector<uint64_t> vectorOfX;

			//Set Entry Size of each rowws in the matrix
			if(k == matrixRowSize-1){
				if((entrySize%cc->GetRingDimension() /*params.ENTRYSIZE*/) != 0)
					entrySizeForRow = entrySize%cc->GetRingDimension() /*params.ENTRYSIZE*/;
				else
					entrySizeForRow = cc->GetRingDimension()/*params.ENTRYSIZE*/;
			}
			else
				entrySizeForRow = cc->GetRingDimension() /*params.ENTRYSIZE*/;


			for(size_t j = 0; j < entrySizeForRow; j++){

				double value = 1;
				DecimalIncrement(value, value, params.PRECISIONDECIMALSIZEX, params);
				vectorOfX.push_back(value);
			}
			x(k, i) =  cc->MakePackedPlaintext(vectorOfX);
		}
    }

    for(size_t i = 2; i < dataColumns.size(); i++) {
    // rows
    	size_t matrixRowIndex = 0;
    	for(size_t k = 0; k < matrixRowSize; k++) {
    		vector<uint64_t> vectorOfX;
    			//Set Entry Size of each rowws in the matrix
   			if(k == matrixRowSize-1){
   				if((entrySize%cc->GetRingDimension() /*params.ENTRYSIZE*/) != 0)
   					entrySizeForRow = entrySize%cc->GetRingDimension() /*params.ENTRYSIZE*/;
   				else
   					entrySizeForRow = cc->GetRingDimension() /*params.ENTRYSIZE*/;
   			}
   			else
   				entrySizeForRow = cc->GetRingDimension() /*params.ENTRYSIZE*/;

   			for(size_t j = 0; j < entrySizeForRow; j++){

   				double value;
   				DecimalIncrement(dataColumns[i][matrixRowIndex], value, params.PRECISIONDECIMALSIZEX, params);
   				vectorOfX.push_back(value);
   				matrixRowIndex++;
    		}
    		x(k, i-1) =  cc->MakePackedPlaintext(vectorOfX);
    	}
    }

    for(size_t i = 1; i < 2; i++) {
	// rows
    	size_t matrixRowIndex = 0;
		for(size_t k = 0; k < matrixRowSize; k++) {
			vector<uint64_t> vectorOfY;

			//Set Entry Size of each rowws in the matrix
			if(k == matrixRowSize-1){
				if((entrySize%cc->GetRingDimension() /*params.ENTRYSIZE*/) != 0)
					entrySizeForRow = entrySize%cc->GetRingDimension() /*params.ENTRYSIZE*/;
				else
					entrySizeForRow = cc->GetRingDimension() /*params.ENTRYSIZE*/;
			}
			else
				entrySizeForRow = cc->GetRingDimension() /*params.ENTRYSIZE*/;


			for(size_t j = 0; j < entrySizeForRow; j++){

				double value;
   				DecimalIncrement(dataColumns[i][matrixRowIndex], value, params.PRECISIONDECIMALSIZE, params);
   				vectorOfY.push_back(value);
   				matrixRowIndex++;
			}
			y(k, 0) =  cc->MakePackedPlaintext(vectorOfY);
		}
    }
}

void EncodeC0Matrix(vector<CryptoContext<DCRTPoly>> &cc, vector<shared_ptr<Matrix<double>>> &CList, vector<shared_ptr<Matrix<Plaintext>>> &CP, vector<NativeInteger> &primeList, size_t &batchSize){

	BigInteger Q, q;

	q.SetValue(primeList[0].ToString());
	Q.SetValue(primeList[0].ToString());
	for(size_t k=1; k<primeList.size(); k++){
		q.SetValue(primeList[k].ToString());
		Q = Q*q;
	}

	BigInteger temp;
	uint64_t tempPushed;
	for(size_t k=0; k<primeList.size(); k++){

		auto zeroPackingAlloc = [=]() { return cc[k]->MakePackedPlaintext({0}); };
		shared_ptr<Matrix<Plaintext>> CPt (new Matrix<Plaintext>(zeroPackingAlloc, (*CList[k]).GetRows(), CList.size()));

		for(size_t i=0; i<CList.size(); i++){
			for(size_t l=0; l<(*CList[k]).GetRows(); l++){
				std::vector<uint64_t> vectorOfInts1;
				for(size_t j=0; j<batchSize; j++){

					if((*CList[i])(l, j)<0)
						temp = Q-BigInteger((*CList[i])(l, j)*(-1));
					else
						temp = BigInteger((*CList[i])(l, j));

					tempPushed = (temp.Mod(primeList[k])).ConvertToInt();
					vectorOfInts1.push_back(tempPushed);
				}
				(*CPt)(l, i) = cc[k]->MakePackedPlaintext(vectorOfInts1);
			}
		}
		CP.push_back(CPt);
	}
}

void EncodeC1Matrix(vector<CryptoContext<DCRTPoly>> &cc, shared_ptr<Matrix<double>> &CList, vector<shared_ptr<Matrix<Plaintext>>> &CP, vector<NativeInteger> &primeList, size_t &batchSize){

	BigInteger Q, q;

	q.SetValue(primeList[0].ToString());
	Q.SetValue(primeList[0].ToString());
	for(size_t k=1; k<primeList.size(); k++){
		q.SetValue(primeList[k].ToString());
		Q = Q*q;
	}

	BigInteger temp;
	uint64_t tempPushed;
	for(size_t k=0; k<primeList.size(); k++){

		auto zeroPackingAlloc = [=]() { return cc[k]->MakePackedPlaintext({0}); };
		shared_ptr<Matrix<Plaintext>> CPt (new Matrix<Plaintext>(zeroPackingAlloc, (*CList).GetRows(), (*CList).GetCols()));

//#pragma omp parallel for shared(CList, CPt, cc, Q, primeList) private(temp, tempPushed) num_threads(8) collapse(2)
		for(size_t i=0; i<(*CList).GetRows(); i++){
			for(size_t j=0; j<(*CList).GetCols(); j++){

				std::vector<uint64_t> vectorOfInts1;

				if((*CList)(i, j)<0){
					double  negT = (*CList)(i, j)*(-1);
					doubleToBigInteger2(negT, temp);
					temp = Q-temp;
				}
				else{
					double  negT = (*CList)(i, j);
					doubleToBigInteger2(negT, temp);
				}
				tempPushed = (temp.Mod(primeList[k])).ConvertToInt();

				for(size_t l=0; l<batchSize; l++){
					vectorOfInts1.push_back(tempPushed);
				}
				(*CPt)(i, j) = cc[k]->MakePackedPlaintext(vectorOfInts1);
			}
		}
		CP.push_back(CPt);
	}
}

void EncodeC1Matrix(vector<CryptoContext<DCRTPoly>> &cc, shared_ptr<Matrix<BigInteger>> &CList, vector<shared_ptr<Matrix<Plaintext>>> &CP, vector<NativeInteger> &primeList, size_t &batchSize){

	BigInteger Q, q;

	q.SetValue(primeList[0].ToString());
	Q.SetValue(primeList[0].ToString());
	for(size_t k=1; k<primeList.size(); k++){
		q.SetValue(primeList[k].ToString());
		Q = Q*q;
	}

	BigInteger temp;
	uint64_t tempPushed;
	for(size_t k=0; k<primeList.size(); k++){

		auto zeroPackingAlloc = [=]() { return cc[k]->MakePackedPlaintext({0}); };
		shared_ptr<Matrix<Plaintext>> CPt (new Matrix<Plaintext>(zeroPackingAlloc, (*CList).GetRows(), (*CList).GetCols()));

		for(size_t i=0; i<(*CList).GetRows(); i++){
			for(size_t j=0; j<(*CList).GetCols(); j++){
				//FIXME: MAKE MORE EFFICIENT
				std::vector<uint64_t> vectorOfInts1;
				for(size_t l=0; l<batchSize; l++){

					temp = (*CList)(i, j);

					tempPushed = (temp.Mod(primeList[k])).ConvertToInt();
					vectorOfInts1.push_back(tempPushed);
				}
				(*CPt)(i, j) = cc[k]->MakePackedPlaintext(vectorOfInts1);
			}
		}
		CP.push_back(CPt);
	}
}


void EncodeC2Matrix(vector<CryptoContext<DCRTPoly>> &cc, shared_ptr<Matrix<double>> &CList, vector<shared_ptr<Matrix<Plaintext>>> &CP, vector<NativeInteger> &primeList, size_t &batchSize){

	BigInteger Q, q;

	q.SetValue(primeList[0].ToString());
	Q.SetValue(primeList[0].ToString());
	for(size_t k=1; k<primeList.size(); k++){
		q.SetValue(primeList[k].ToString());
		Q = Q*q;
	}

	BigInteger temp;
	uint64_t tempPushed;
	for(size_t k=0; k<primeList.size(); k++){

		auto zeroPackingAlloc = [=]() { return cc[k]->MakePackedPlaintext({0}); };
		shared_ptr<Matrix<Plaintext>> CPt (new Matrix<Plaintext>(zeroPackingAlloc, (*CList).GetRows(), 1));

			for(size_t l=0; l<(*CList).GetRows(); l++){
				std::vector<uint64_t> vectorOfInts1;
				for(size_t j=0; j<batchSize; j++){

					if((*CList)(l, j)<0)
						temp = Q-BigInteger((*CList)(l, j)*(-1));//temp = (*CList)(l, j) + Q.ConvertToDouble();
					else
						temp = BigInteger((*CList)(l, j));


					tempPushed = (temp.Mod(primeList[k])).ConvertToInt();
					vectorOfInts1.push_back(tempPushed);
				}
				(*CPt)(l, 0)= cc[k]->MakePackedPlaintext(vectorOfInts1);
		}
	CP.push_back(CPt);
	}
}

/////////////////////////////////////////////////////////////////////////
/////////                     Decimal Scaling Functions         /////////
/////////////////////////////////////////////////////////////////////////

void DecimalIncrement(const vector<shared_ptr<Matrix<double>>> &in, vector<shared_ptr<Matrix<double>>> &out, size_t decimalSize, glmParams &params){

	double decimal = params.PRECISION;
	for(size_t i=1; i<decimalSize; i++)
		decimal = decimal*params.PRECISION;

	for(size_t k=0; k<in.size(); k++){
		for(size_t i=0; i<(*in[k]).GetRows(); i++){
			for(size_t j=0; j<(*in[k]).GetCols(); j++)
				(*out[k])(i, j) = (*in[k])(i, j)*decimal;
		}
	}
}

void DecimalDecrement(const vector<shared_ptr<Matrix<double>>> &in, vector<shared_ptr<Matrix<double>>> &out, size_t decimalSize, glmParams &params){

	double decimal = params.PRECISION;
	for(size_t i=1; i<decimalSize; i++)
		decimal = decimal*params.PRECISION;

	for(size_t k=0; k<in.size(); k++){
		for(size_t i=0; i<(*in[k]).GetRows(); i++){
			for(size_t j=0; j<(*in[k]).GetCols(); j++)
				(*out[k])(i, j) = (*in[k])(i, j)/decimal;
		}
	}
}

void DecimalIncrement(const Matrix<double> &in, Matrix<double> &out, size_t decimalSize, glmParams &params){

	double decimal = params.PRECISION;
	for(size_t i=1; i<decimalSize; i++)
		decimal = decimal*params.PRECISION;

	for(size_t i=0; i<in.GetRows(); i++){
		for(size_t j=0; j<in.GetCols(); j++)
			out(i, j) = in(i, j)*decimal;
	}
}

void DecimalDecrement(const Matrix<double> &in, Matrix<double> &out, size_t decimalSize, glmParams &params){

	double decimal = params.PRECISION;
	for(size_t i=1; i<decimalSize; i++)
		decimal = decimal*params.PRECISION;

	for(size_t i=0; i<in.GetRows(); i++){
		for(size_t j=0; j<in.GetCols(); j++)
			out(i, j) = in(i, j)/decimal;
	}
}

void DecimalIncrement(const double &in, double &out, size_t decimalSize, glmParams &params){

	double decimal = params.PRECISION;
	for(size_t i=1; i<decimalSize; i++)
		decimal = decimal*params.PRECISION;

	out = in*decimal;
}

void DecimalDecrement(const double &in, double &out, size_t decimalSize, glmParams &params){

	double decimal = params.PRECISION;
	for(size_t i=1; i<decimalSize; i++)
		decimal = decimal*params.PRECISION;

	out = in/decimal;
}

/////////////////////////////////////////////////////////////////////////
/////////                     Printing Functions                /////////
/////////////////////////////////////////////////////////////////////////
void PrintMatrixDouble(const Matrix<double> &in){

	for(size_t i=0; i<in.GetRows(); i++){
		for(size_t j=0; j<in.GetCols(); j++)
			cout << std::setprecision(15) << in(i, j) << "\t";

		cout << endl;
	}
}

/////////////////////////////////////////////////////////////////////////
/////////                     Conversion Functions              /////////
/////////////////////////////////////////////////////////////////////////
void doubleToBigInteger(double &in, BigInteger &out){

	string s, temp;
	s = to_string(in);
	out = 0;
	for(size_t i=0; i<s.size(); i++){

		temp = s[i];
		if(temp == ".")
			break;
		else{
			out = out*BigInteger(10) + BigInteger(atoi(temp.c_str()));
		}
	}
}

void doubleToBigInteger2(double &in, BigInteger &out){

	uint64_t castDouble, exp, sign, fraction;
	memcpy(&castDouble, &in, sizeof(in));

	exp = castDouble >> 52;

	sign = exp >> 11;
	exp  = exp & 0x7F;

	fraction = castDouble & 0xFFFFFFFFFFFFF;
	fraction = fraction | (1UL << 52);

	exp = exp - 1023;
	exp = 52 - exp;

	fraction = fraction >> exp;

	out = BigInteger(fraction);
	if(sign == 1)
		out = out*(-1);


//	cout << in << endl;
//	cout << out << endl;


/*
	vector<BigInteger> scale;

	scale[0] = BigInteger(10);
	for(size_t i=1; i<10; i++)
		scale[i] = scale[i-1]*BigInteger(10);

	string s, temp;

	s = to_string(in);

	size_t position = s.find(".");
	s = s.substr(0, position);


	size_t loopSize = s.length()/10;
	if(s.length()%10 == 0)
		loopSize++;

	out = 0;
	for(size_t i=0; i<loopSize; i++){

		if(i == (loopSize-1)){
			temp = s.substr(0, s.length()-1);
			out = out*scale[s.length()-1] + BigInteger(atoi(temp.c_str()));
		}
		else{
			temp = s.substr(0, 10);
			out = out*scale[9] + BigInteger(atoi(temp.c_str()));
		}

		if(i != (loopSize-1))
			s = s.substr(10, s.length()-1);
	}


*/











/*


	bool loop = true;

	while(loop){

		temp = s.substr(0, 10);

		out = out*scale + BigInteger(atoi(temp.c_str()));


	}

*/

/*
	out = 0;
	for(size_t i=0; i<s.size(); i++){

		temp = s[i];
		if(temp == ".")
			break;
		else{
			out = out*BigInteger(10) + BigInteger(atoi(temp.c_str()));
		}
	}
*/
}






