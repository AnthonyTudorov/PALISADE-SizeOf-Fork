#include "ABE/KP_ABE.h"
#include "ABE/CP_ABE.h"
#include "ABE/IBE.h"

using namespace lbcrypto;

int main()
{

//	KPABE_NANDGateTest(10, 8);  // second argument is the base
  //  KPABE_BenchmarkCircuitTest(10,8);
	//KPABE_ANDGateTest(100);
	//KPABE_APolicyCircuitTest(10);


	CPABE_Test(10);


    //IBE_Test(10, 32);
	return 0;
}
