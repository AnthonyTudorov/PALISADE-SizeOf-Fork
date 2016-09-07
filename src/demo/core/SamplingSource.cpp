#include "../../lib/math/discretegaussiangenerator.h"
#include "../../lib/utils/debug.h";
#include <vld.h>
using namespace lbcrypto;

int main() {
	DiscreteGaussianGenerator dgg(4);
	double start, finish;
	/*
	int frequency[41];
	for (int i = 0;i < 41;i++) {
		frequency[i] = 0;
	}
	*/
	start = currentDateTime();
	dgg.GenerateProbMatrix(1,100);
	finish = currentDateTime();
	std::cout << "Probability matrix generation: " << finish - start << " ms\n";

	start = currentDateTime();
	for (int i = 0;i < 1000;i++) {
		dgg.GenerateInteger(100, 1, 64);
	}
	finish = currentDateTime();
	std::cout << "Sampling 1000 integers (Rejection): " << finish - start << " ms\n";

	start = currentDateTime();
	for (int i = 0;i < 1000;i++) {
		//frequency[dgg.GenerateIntegerKnuthYao()+20-10] += 1;
		dgg.GenerateIntegerKnuthYao();
	}
	finish = currentDateTime();
	std::cout << "Sampling 1000 integers (Knuth-Yao): " << finish - start << " ms\n";
	/*
	for (int i = 0;i < 41;i++) {
		std::cout << i - 20+10<< " : " << frequency[i] << std::endl;
	}
	*/
	std::cin.ignore();
	std::cin.get();
	return 0;
}