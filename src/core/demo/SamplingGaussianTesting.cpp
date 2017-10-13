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
#include <fstream>
using namespace lbcrypto;

int main() {
	double std= 4;
	double mean = 0;
	std::ofstream outputFile;
	DiscreteGaussianGeneratorGeneric dgg(std);
	std::vector<int64_t> histogram(16*std+1,0);
	int count = 10000000;
	dgg.PreCompute(1,1,std);
	//dgg.GenerateProbMatrix(std,0,1);
	for(int i=0;i<count;i++){
		/*int64_t number=*/
		//std::cout<<dgg.GenerateIntegerPeikert(0)<<std::endl;
		//histogram[number+8*std]++;
	}

	outputFile.open("peikert_samples");
	/*std::shared_ptr<int> numbers = dgg.GenerateIntVector(count);
	for(int i=0;i<count;i++){
		histogram[(numbers.get())[i]+8*std]++;
	}*/

	for(int i=0;i<=16*std;i++){
		//outputFile<<(i-8*std)<<", "<<histogram[i]<<",\n";
	}
	outputFile.close();
	std::cout<<"Sample histogram generated\n";
}

