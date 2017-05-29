#include "math/discretegaussiangenerator.h"
#include "utils/debug.h"
//#include <vld.h>
using namespace lbcrypto;

int main() {
	double std = 10000;
	DiscreteGaussianGenerator dgg(std);
	double start, finish;

	size_t count = 100000;

	start = currentDateTime();
	dgg.GenerateProbMatrix(std, 0);
	finish = currentDateTime();
	std::cout << "Probability matrix generation: " << finish - start << " ms\n";

	start = currentDateTime();
	for (size_t i = 0;i < count;i++) {
		dgg.GenerateInteger(0, std, 1024);
	}
	finish = currentDateTime();
	std::cout << "Sampling 100000 integers (Rejection): " << finish - start << " ms\n";

	start = currentDateTime();
	for (size_t i = 0;i < count;i++) {
		//dgg.GenerateIntegerKnuthYao();
	}
	finish = currentDateTime();
	std::cout << "Sampling 100000 integers (Knuth-Yao): " << finish - start << " ms\n";

	start = currentDateTime();
	dgg.GenerateIntVector(count);
	finish = currentDateTime();
	std::cout << "Sampling 100000 integers (Peikert): " << finish - start << " ms\n";

	std::cin.ignore();
	std::cin.get();
	return 0;
}
