/*
 * glminterface.h
 *
 *  Created on: Feb 16, 2018
 *      Author: dante
 */

#ifndef SRC_WRAPPERS_PYTHON_GLMINTERFACE_H_
#define SRC_WRAPPERS_PYTHON_GLMINTERFACE_H_

#define BOOST_PYTHON_STATIC_LIB //needed for Windows

#include <iostream>
#include <fstream>

#include "time.h"
#include <chrono>
#include "utils/debug.h"

#include <boost/python.hpp>

#include "wip/lib/glm/glmfunctions.h"

namespace glmcrypto {


	class GLMClient {

		public:

			GLMClient() {};
			~GLMClient() {};

			void KeyGen(const string keyDir,
						const string keyfileName,
						const boost::python::list& pythonList);

			void Encrypt(const string keyDir,
						 const string keyfileName,
						 const string plaintextDataDir,
						 const string plaintextDataFileName,
						 const string ciphertextDataDir,
						 const string ciphertextDataFileName,
						 const string ciphertextXFileName,
						 const string ciphertextYFileName,
						 const string ciphertextWFileName,
						 const boost::python::list& pythonList);

			double ComputeError(const string keyDir,
								const string keyfileName,
								const string ciphertextDataDir,
								const string ciphertextDataFileName,
								const string ciphertextMUFileName,
								const string ciphertextYFileName,
								const boost::python::list& pythonList);

			void Step1ComputeLink(const string keyDir,
					   	    const string keyfileName,
							const string ciphertextDataDir,
							const string ciphertextDataFileName,
							const string ciphertextMUFileName,
							const string ciphertextSFileName,
							const string ciphertextXWFileName,
							const string ciphertextYFileName,
							const string regAlgorithm,
							const boost::python::list& pythonList);

			void Step2RescaleC1(const string keyDir,
		 	 	 	   	   	  const string keyfileName,
							  const string ciphertextDataDir,
							  const string ciphertextDataFileName,
							  const string ciphertextC1FileName,
							  const boost::python::list& pythonList);

			vector<double> Step3RescaleRegressor(const string keyDir,
								  const string keyfileName,
								  const string ciphertextDataDir,
								  const string ciphertextDataFileName,
								  const string ciphertextC1C2FileName,
								  const string ciphertextWFileName,
								  const boost::python::list& pythonList);

			void PrintTimings();

	};

	class GLMServer {

		public:

			void Step1ComputeXW(const string keyDir,
					  const string keyfileName,
					  const string ciphertextDataDir,
					  const string ciphertextDataFileName,
					  const string ciphertextXFileName,
					  const string ciphertextWFileName,
					  const string ciphertextResultFileName,
					  const boost::python::list& pythonList);

			void Step2ComputeXTSX(const string keyDir,
						  const string keyfileName,
						  const string ciphertextDataDir,
						  const string ciphertextDataFileName,
						  const string ciphertextResultFileName,
						  const string ciphertextSFileName,
						  const string ciphertextXFileName,
						  const string ciphertextC1FileName,
						  const boost::python::list& pythonList);

			void Step3ComputeRegressor(const string keyDir,
							const string keyfileName,
							const string ciphertextDataDir,
							const string ciphertextDataFileName,
							const string ciphertextWFileName,
							const string ciphertextXFileName,
							const string ciphertextYFileName,
							const string ciphertextMUFileName,
							const string ciphertextC1FileName,
							const string ciphertextC1C2FileName,
							const boost::python::list& pythonList);

			void PrintTimings();

	};

	vector<uint64_t> pythonListToCppVector(const boost::python::list& pythonList);
	void vectorToGlmParams(glmParams &g, vector<uint64_t> &l);

}

#endif /* SRC_WRAPPERS_PYTHON_GLMINTERFACE_H_ */
