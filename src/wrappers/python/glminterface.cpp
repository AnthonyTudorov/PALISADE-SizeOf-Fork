/*
 * glminterface.cpp
 *
 *  Created on: Feb 16, 2018
 *      Author: dante
 */

#include "glminterface.h"


namespace glmcrypto{

/////////////////////////////////////////////////////////////////////////////////////
////////////////////////////   CLIENT   /////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

	void GLMClient::KeyGen(const string keyDir,
					 const string keyfileName,
					 const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
		GLMKeyGen(keyDir, keyfileName, glmParam);
	}


	void GLMClient::Encrypt(const string keyDir,
			 	 	  const string keyfileName,
					  const string plaintextDataDir,
					  const string plaintextDataFileName,
					  const string ciphertextDataDir,
					  const string ciphertextDataFileName,
					  const string ciphertextXFileName,
					  const string ciphertextYFileName,
					  const string ciphertextWFileName,
					  const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
		GLMEncrypt(keyDir, keyfileName, plaintextDataDir, plaintextDataFileName, ciphertextDataDir, ciphertextDataFileName,
				ciphertextXFileName, ciphertextYFileName, ciphertextWFileName, glmParam);
	}

	double GLMClient::ComputeError(const string keyDir,
			   	   	   	 const string keyfileName,
						 const string ciphertextDataDir,
						 const string ciphertextDataFileName,
						 const string ciphertextMUFileName,
						 const string ciphertextYFileName,
						 const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);

		return GLMClientComputeError(keyDir, keyfileName, ciphertextDataDir, ciphertextDataFileName,
				ciphertextMUFileName, ciphertextYFileName, glmParam);
	}

	void GLMClient::Step1ComputeLink(const string keyDir,
			   	   	   	 const string keyfileName,
						 const string ciphertextDataDir,
						 const string ciphertextDataFileName,
						 const string ciphertextMUFileName,
						 const string ciphertextSFileName,
						 const string ciphertextXWFileName,
						 const string ciphertextYFileName,
						 const string regAlgorithm,
						 const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
		GLMClientLink(keyDir, keyfileName, ciphertextDataDir, ciphertextDataFileName,
				ciphertextMUFileName, ciphertextSFileName, ciphertextXWFileName, ciphertextYFileName, regAlgorithm, glmParam);
	}

	void GLMClient::Step2RescaleC1(const string keyDir,
 	 	 	   const string keyfileName,
			   const string ciphertextDataDir,
			   const string ciphertextDataFileName,
			   const string ciphertextC1FileName,
			   const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
		GLMClientRescaleC1(keyDir, keyfileName, ciphertextDataDir, ciphertextDataFileName, ciphertextC1FileName, glmParam);
	}

	vector<double> GLMClient::Step3RescaleRegressor(const string keyDir,
						  const string keyfileName,
						  const string ciphertextDataDir,
						  const string ciphertextDataFileName,
						  const string ciphertextC0C1C2FileName,
						  const string ciphertextWFileName,
						  const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
		return GLMClientRescaleRegressor(keyDir, keyfileName, ciphertextDataDir,
						 ciphertextDataFileName, ciphertextC0C1C2FileName, ciphertextWFileName, glmParam);
	}

	void GLMClient::PrintTimings(){
#ifdef MEASURE_TIMING
		GLMPrintTimings("Client");
#endif
	}

/////////////////////////////////////////////////////////////////////////////////////
////////////////////////////   SERVER  //////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

	void GLMServer::Step1ComputeXW(const string keyDir,
					   const string keyfileName,
					   const string ciphertextDataDir,
					   const string ciphertextDataFileName,
					   const string ciphertextXFileName,
					   const string ciphertextWFileName,
					   const string ciphertextResultFileName,
					   const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
		GLMServerXW(keyDir, keyfileName, ciphertextDataDir, ciphertextDataFileName,
				ciphertextXFileName, ciphertextWFileName, ciphertextResultFileName, glmParam);
	}

	void GLMServer::Step2ComputeXTSX(const string keyDir,
					   const string keyfileName,
					   const string ciphertextDataDir,
					   const string ciphertextDataFileName,
					   const string ciphertextResultFileName,
					   const string ciphertextSFileName,
					   const string ciphertextXFileName,
					   const string ciphertextC1FileName,
					   const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
		GLMServerXTSX(keyDir, keyfileName, ciphertextDataDir, ciphertextDataFileName,
				ciphertextSFileName, ciphertextXFileName, ciphertextC1FileName, glmParam);
	}

	void GLMServer::Step3ComputeRegressor(const string keyDir,
					   	 const string keyfileName,
					     const string ciphertextDataDir,
					     const string ciphertextDataFileName,
						 const string ciphertextWFileName,
						 const string ciphertextXFileName,
						 const string ciphertextYFileName,
						 const string ciphertextMUFileName,
					     const string ciphertextC1FileName,
						 const string ciphertextC1C2FileName,
						 const boost::python::list& pythonList){

		glmParams glmParam;
		std::vector<uint64_t> glmParamVector = pythonListToCppVector(pythonList);
		vectorToGlmParams(glmParam, glmParamVector);
		GLMServerComputeRegressor(keyDir, keyfileName, ciphertextDataDir, ciphertextDataFileName,
						ciphertextWFileName, ciphertextXFileName, ciphertextYFileName, ciphertextMUFileName,
						ciphertextC1FileName, ciphertextC1C2FileName, glmParam);

	}

	void GLMServer::PrintTimings(){
#ifdef MEASURE_TIMING
		GLMPrintTimings("Server");
#endif
	}

/////////////////////////////////////////////////////////////////////////////////////
////////////////////////////    UTIL    /////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

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

	vector<uint64_t> pythonListToCppVector(const boost::python::list& pythonList) {

		vector<uint64_t> cppVector;

		for (unsigned int i = 0; i < len(pythonList); i++) {
			cppVector.push_back(boost::python::extract<uint64_t>(pythonList[i]));
		}

		return cppVector;
	}

}
