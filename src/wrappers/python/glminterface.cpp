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

	void GLMClient::KeyGen(){

		GLMKeyGen(path, glmParam);
	}

	void GLMClient::Encrypt(){

		GLMEncrypt(path, glmParam);
	}

	double GLMClient::ComputeError(){

		return GLMClientComputeError(path, glmParam);
	}

	void GLMClient::Step1ComputeLink(const string regAlgorithm){

		GLMClientLink(path, glmParam, regAlgorithm);
	}

	void GLMClient::Step2RescaleC1(){

		GLMClientRescaleC1(path, glmParam);
	}

	vector<double> GLMClient::Step3RescaleRegressor(){

		return GLMClientRescaleRegressor(path, glmParam);
	}

	void GLMClient::PrintTimings(){
#ifdef MEASURE_TIMING
		GLMPrintTimings("Client");
#endif
	}

/////////////////////////////////////////////////////////////////////////////////////
////////////////////////////   SERVER  //////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

	void GLMServer::SetFileNamesPaths(const boost::python::list& pythonList){

		vector<string> vecList = pythonListToCppStringVector(pythonList);
		vectorToPathList(path, vecList);
	}

	void GLMServer::SetGLMParams(const boost::python::list& pythonList){

		std::vector<uint64_t> glmParamVector = pythonListToCppIntVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
	}

	void GLMServer::Step1ComputeXW(){

		GLMServerXW(path, glmParam);
	}

	void GLMServer::Step2ComputeXTSX(){

		GLMServerXTSX(path, glmParam);
	}

	void GLMServer::Step3ComputeRegressor(){

		GLMServerComputeRegressor(path, glmParam);
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










