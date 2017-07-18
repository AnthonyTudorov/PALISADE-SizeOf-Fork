#include "ABE/KP_ABE.h"
#include "ABE/CP_ABE.h"
#include "ABE/IBE.h"

using namespace lbcrypto;

int main()
{

	std::cout << "-------Start demo for KP-ABE-------" << std::endl;
	KPABE_BenchmarkCircuitTest(1,8);
	std::cout << "-------End demo for KP-ABE-------" << std::endl << std::endl;

	std::cout << "-------Start demo for CP-ABE-------" << std::endl;
	CPABE_Test(1);
	std::cout << "-------End demo for CP-ABE-------" << std::endl << std::endl;

	std::cout << "-------Start demo for IBE-------" << std::endl;
	IBE_Test(1,16);
	std::cout << "-------End demo for IBE-------" << std::endl << std::endl;

	return 0;
}
