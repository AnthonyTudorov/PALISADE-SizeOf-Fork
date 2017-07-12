#include "ABE/KP_ABE.h"
#include "ABE/CP_ABE.h"
#include "ABE/IBE.h"

using namespace lbcrypto;

int main()
{
	std::cout << "Merhaba Dunya!" << std::endl;

	//KPABE_NANDGateTest(10, 32);  // second argument is the base
      KPABE_BenchmarkCircuitTest(10,8);
	//ErrorRatesSi(0);
	//KPABE_ANDGateTest(100);
	//KPABE_APolicyCircuitTest(10);
	//BitSizes(4, 10);
	//BitSizeswNAFDecompose(10, 10);
	//BitSizesBinaryDecompose(6, 10);
	//Decompose_Experiments(2);
	//Poly2NAFDecompose(0);
	//TestNAFDecomp(1);
	//TestBalDecomp (1, 32); // second argument is the base

	//TestTernaryBase_01 (0);
	//CPABE_Test(10);


    //IBE_Test(10, 32);
	return 0;
}
