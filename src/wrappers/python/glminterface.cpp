/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers:
*		Dr. Yarkin Doroz, <ydoroz@njit.edu>
* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2016, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONT0RIBUTORS "AS IS" AND
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
* Python wrapper class for generalized linear method
*/

#include "glminterface.h"


namespace glmcrypto{

/////////////////////////////////////////////////////////////////////////////////////
////////////////////////////   CLIENT   /////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

	void GLMClient::SetFileNamesPaths(const boost::python::list& pythonList){

		vector<string> vecList = pythonListToCppStringVector(pythonList);
		vectorToPathList(path, vecList);
	}

	void GLMClient::SetGLMParams(const boost::python::list& pythonList){

		std::vector<uint64_t> glmParamVector = pythonListToCppIntVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
	}

	void GLMClient::SetGLMContext(){

		for(size_t k = 0; k < glmParam.PLAINTEXTPRIMESIZE; k++) {

			string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
			string emFileName = path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt";
			string esFileName = path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt";
			string pkFileName = path.keyDir+"/"+path.keyfileName+"-public" + std::to_string(k) + ".txt";
			string skFileName = path.keyDir+"/"+path.keyfileName+"-private" + std::to_string(k) + ".txt";

			// Deserialize the crypto context
			CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
			context.cc.push_back(cct);

			context.cc[k]->Enable(ENCRYPTION);
			context.cc[k]->Enable(SHE);

			size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
			EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
			PackedEncoding::SetParams(m, encodingParams);

			DeserializeEvalSum(context.cc[k], esFileName);
			DeserializeEvalMult(context.cc[k], emFileName);

			string pathToFile;
			pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-" + path.ciphertextXFileName + "-" + std::to_string(k) + ".txt";
			shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xt = DeserializeCiphertext(context.cc[k], pathToFile);
			context.x.push_back(xt);

			pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextYFileName+"-" + std::to_string(k) + ".txt";
			shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yt = DeserializeCiphertext(context.cc[k], pathToFile);
			context.y.push_back(yt);

			LPPublicKey<DCRTPoly> pkt = DeserializePublicKey(context.cc[k], pkFileName);
			context.pk.push_back(pkt);

			LPPrivateKey<DCRTPoly> skt = DeserializePrivateKey(context.cc[k], skFileName);
			context.sk.push_back(skt);
		}
	}

	void GLMClient::KeyGen(){

		GLMKeyGen(path, glmParam);
	}

	void GLMClient::Encrypt(){

		GLMEncrypt(context, path, glmParam);
	}

	double GLMClient::ComputeError(){

		return GLMClientComputeError(context, path, glmParam);
	}

	void GLMClient::Step1ComputeLink(const string regAlgorithm){

		GLMClientLink(context, path, glmParam, regAlgorithm);
	}

	void GLMClient::Step2RescaleC1(){

		GLMClientRescaleC1(context, path, glmParam);
	}

	vector<double> GLMClient::Step3RescaleRegressor(){

		return GLMClientRescaleRegressor(context, path, glmParam);
	}

	void GLMClient::PrintTimings(){
#ifdef MEASURE_TIMING
		GLMPrintTimings("Client");
#endif
	}

/////////////////////////////////////////////////////////////////////////////////////
////////////////////////////   SERVER  //////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

	void GLMServer::SetGLMContext(){

		for(size_t k = 0; k < glmParam.PLAINTEXTPRIMESIZE; k++) {

			string ccFileName = path.keyDir+"/"+path.keyfileName+"-cryptocontext" + std::to_string(k) + ".txt";
			string emFileName = path.keyDir+"/"+path.keyfileName+"-eval-mult" + std::to_string(k) + ".txt";
			string esFileName = path.keyDir+"/"+path.keyfileName+"-eval-sum" + std::to_string(k) + ".txt";

			// Deserialize the crypto context
			CryptoContext<DCRTPoly> cct = DeserializeContext(ccFileName);
			context.cc.push_back(cct);

			context.cc[k]->Enable(ENCRYPTION);
			context.cc[k]->Enable(SHE);

			size_t m = context.cc[k]->GetCyclotomicOrder(); //params.CYCLOTOMICM;
			EncodingParams encodingParams = context.cc[k]->GetEncodingParams();
			PackedEncoding::SetParams(m, encodingParams);

			DeserializeEvalSum(context.cc[k], esFileName);
			DeserializeEvalMult(context.cc[k], emFileName);

			string pathToFile;
			pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-" + path.ciphertextXFileName + "-" + std::to_string(k) + ".txt";
			shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xt = DeserializeCiphertext(context.cc[k], pathToFile);
			context.x.push_back(xt);

			pathToFile = path.ciphertextDataDir+"/"+path.ciphertextDataFileName+"-"+path.ciphertextYFileName+"-" + std::to_string(k) + ".txt";
			shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> yt = DeserializeCiphertext(context.cc[k], pathToFile);
			context.y.push_back(yt);
		}

		//This is to create a dummy computation to create multiplication tables for BFVrns.
		//This prevents problems in OpenMP threading.
		for(size_t k = 0; k < glmParam.PLAINTEXTPRIMESIZE; k++) {

			std::vector<uint64_t> vectorOfInts1;
			vectorOfInts1.push_back(0);

			Plaintext intArray1 = context.cc[k]->MakePackedPlaintext(vectorOfInts1);

	    	Ciphertext<DCRTPoly> c1 = context.cc[k]->Encrypt(context.pk[k], intArray1);
	    	Ciphertext<DCRTPoly> c2 = context.cc[k]->Encrypt(context.pk[k], intArray1);

		    Ciphertext<DCRTPoly> t  = context.cc[k]->EvalMult(c1, c2);
	    }
	}

	void GLMServer::SetFileNamesPaths(const boost::python::list& pythonList){

		vector<string> vecList = pythonListToCppStringVector(pythonList);
		vectorToPathList(path, vecList);
	}

	void GLMServer::SetGLMParams(const boost::python::list& pythonList){

		std::vector<uint64_t> glmParamVector = pythonListToCppIntVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
	}

	void GLMServer::Step1ComputeXW(){

		GLMServerXW(context, path, glmParam);
	}

	void GLMServer::Step2ComputeXTSX(){

		GLMServerXTSX(context, path, glmParam);
	}

	void GLMServer::Step3ComputeRegressor(){

		GLMServerComputeRegressor(context, path, glmParam);
	}

	void GLMServer::PrintTimings(){
#ifdef MEASURE_TIMING
		GLMPrintTimings("Server");
#endif
	}

/////////////////////////////////////////////////////////////////////////////////////
////////////////////////////    UTIL    /////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

	vector<uint64_t> pythonListToCppIntVector(const boost::python::list& pythonList) {

		vector<uint64_t> cppVector;

		for (unsigned int i = 0; i < len(pythonList); i++) {
			cppVector.push_back(boost::python::extract<uint64_t>(pythonList[i]));
		}

		return cppVector;
	}

	vector<string> pythonListToCppStringVector(const boost::python::list& pythonList) {

		vector<string> cppVector;

		for (unsigned int i = 0; i < len(pythonList); i++) {
			cppVector.push_back(boost::python::extract<string>(pythonList[i]));
		}

		return cppVector;
	}

	void vectorToGlmParams(glmParams &g, vector<uint64_t> &l){

		g.MAXVALUE = l[0];
		g.PRECISION = l[1];
		g.PRECISIONDECIMALSIZE = l[2];
		g.PRECISIONDECIMALSIZEX = l[3];

		g.PLAINTEXTPRIMESIZE = l[4];
		g.PLAINTEXTBITSIZE = l[5];

		g.REGRLOOPCOUNT = l[6];

		g.NUMTHREADS = l[7];
	}

	void vectorToPathList(pathList &path, vector<string> &vecList){

		path.keyDir					= vecList[0];
		path.keyfileName			= vecList[1];
		path.ciphertextDataDir		= vecList[2];
		path.ciphertextDataFileName	= vecList[3];
		path.plaintextDataDir		= vecList[4];
		path.plaintextDataFileName	= vecList[5];
		path.ciphertextXFileName	= vecList[6];
		path.ciphertextYFileName	= vecList[7];
		path.ciphertextWFileName	= vecList[8];
		path.ciphertextXWFileName	= vecList[9];
		path.ciphertextMUFileName	= vecList[10];
		path.ciphertextSFileName	= vecList[11];
		path.ciphertextC1FileName	= vecList[12];
		path.ciphertextC2FileName	= vecList[13];
		path.ciphertextC1C2FileName = vecList[14];

	}

}










