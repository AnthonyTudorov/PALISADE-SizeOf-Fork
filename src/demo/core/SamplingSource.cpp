#include "../../lib/math/discretegaussiangenerator.h"
#include "../../lib/utils/debug.h";
#include <vld.h>
using namespace lbcrypto;

int main() {
	DiscreteGaussianGenerator dgg(4);
	double start, finish;
	
	start = currentDateTime();
	dgg.GenerateProbMatrix(4, 512);
	finish = currentDateTime();
	std::cout << "Probability matrix generation: " << finish - start << " ms\n";

	start = currentDateTime();
	for (int i = 0;i < 1000;i++) {
		dgg.GenerateInteger(0, 4, 512);
	}
	finish = currentDateTime();
	std::cout << "Sampling 1000 integers (Rejection): " << finish - start << " ms\n";

	start = currentDateTime();
	for (int i = 0;i < 1000;i++) {
		dgg.GenerateIntegerKnuthYao();
	}
	finish = currentDateTime();
	std::cout << "Sampling 1000 integers (Knuth-Yao): " << finish - start << " ms\n";

	return 0;
}