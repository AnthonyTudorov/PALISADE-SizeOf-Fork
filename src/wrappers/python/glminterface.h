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

#ifndef SRC_WRAPPERS_PYTHON_GLMINTERFACE_H_
#define SRC_WRAPPERS_PYTHON_GLMINTERFACE_H_

#define BOOST_PYTHON_STATIC_LIB //needed for Windows

#include <iostream>
#include <fstream>

#include "time.h"
#include <chrono>
#include "utils/debug.h"

#include <boost/python.hpp>

#include "../../wip/lib/glm/glmfunctions.h"

namespace glmcrypto {


	class GLMClient {

		public:

			GLMClient() {};
			~GLMClient() {};

			void KeyGen();

			void Encrypt();

			void SetFileNamesPaths(const boost::python::list& pythonList);

			void SetGLMParams(const boost::python::list& pythonList);

			double ComputeError();

			void Step1ComputeLink(const string regAlgorithm);

			void Step2RescaleC1();

			vector<double> Step3RescaleRegressor();

			void PrintTimings();

		private:

			pathList path;

			glmParams glmParam;

	};

	class GLMServer {

		public:

			void SetFileNamesPaths(const boost::python::list& pythonList);

			void SetGLMParams(const boost::python::list& pythonList);

			void Step1ComputeXW();

			void Step2ComputeXTSX();

			void Step3ComputeRegressor();

			void PrintTimings();

		private:

			pathList path;

			glmParams glmParam;
	};

	vector<uint64_t> pythonListToCppIntVector(const boost::python::list& pythonList);
	vector<string> pythonListToCppStringVector(const boost::python::list& pythonList);

	void vectorToGlmParams(glmParams &g, vector<uint64_t> &l);
	void vectorToPathList(pathList &path, vector<string> &vecList);

}

#endif /* SRC_WRAPPERS_PYTHON_GLMINTERFACE_H_ */






