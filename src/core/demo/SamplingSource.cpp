/*
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
#include "math/discretegaussiangenerator.h"
#include "math/discretegaussiangeneratorgeneric.h"
#include "utils/debug.h"
//#include <vld.h>
using namespace lbcrypto;

int main() {
	//double std = 1000;
	//double std = 10000;

	double stdBase = 100;
	double std = (1<<22);
	int CENTER_COUNT = 1024;


	DiscreteGaussianGenerator dgg(4);
	DiscreteGaussianGenerator dggRejection(4);
	DiscreteGaussianGeneratorGeneric dgg2(100);
	DiscreteGaussianGeneratorGeneric dgg3(stdBase, KNUTH_YAO);
	DiscreteGaussianGenerator dgg4(stdBase); //for Peikert's method
	double start, finish;
	size_t count = 10000;

	std::cout << "Distribution parameter = " << std << std::endl;



	start = currentDateTime();
	for (int k = 0; k < CENTER_COUNT; k++) {
		double center = k/(double)CENTER_COUNT;
		for (size_t i = 0;i < count;i++) {
			dggRejection.GenerateInteger(center, std, 8192);
		}
	}
	finish = currentDateTime();
	std::cout << "Sampling " << std::to_string(count) << " integers (Rejection): " << (finish - start)/CENTER_COUNT << " ms\n";

	start = currentDateTime();
	for (int k = 0;k < CENTER_COUNT;k++) {
		double center = k/(double)CENTER_COUNT;
		for (size_t i = 0;i < count;i++) {
			dgg.GenerateIntegerKarney(center, std);
		}
	}

	finish = currentDateTime();
	std::cout << "Sampling " << std::to_string(count) << " integers (Karney): " << (finish - start)/CENTER_COUNT << " ms\n";

	start = currentDateTime();
	dgg2.PreCompute(CENTER_COUNT, std::ceil(30/log2(CENTER_COUNT)), stdBase);
	finish = currentDateTime();
	std::cout << "Probability matrix generation: " << finish - start << " ms\n";

	start = currentDateTime();
	for (int k = 0; k < CENTER_COUNT; k++) {
		double center = k/(double)CENTER_COUNT;
		for (size_t i = 0;i < count;i++) {
			dgg2.GenerateInteger(center, std); //k/CENTER_COUNT
		}
	}
	finish = currentDateTime();
	std::cout << "Sampling " << std::to_string(count) << " integers (Generic - Peikert): " << (finish - start)/CENTER_COUNT << " ms\n";



	dgg3.PreCompute(CENTER_COUNT, std::ceil(30/log2(CENTER_COUNT)), stdBase);
	//dgg3.GenerateProbMatrix(stdBase,0,1);
	start = currentDateTime();
	for (int k = 0; k < CENTER_COUNT; k++) {
		double center = k/(double)CENTER_COUNT;
		for (size_t i = 0;i < count;i++) {
			dgg3.GenerateInteger(center,std);
			//dgg3.GenerateIntegerKnuthYaoAlt(0);
		}
	}
	finish = currentDateTime();
	std::cout << "Sampling " << std::to_string(count) << " integers (Generic - Knuth Yao): " << (finish - start)/CENTER_COUNT << " ms\n";
}
