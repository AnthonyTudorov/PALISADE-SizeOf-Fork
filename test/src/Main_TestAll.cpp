#include <iostream>

//#include "UnitTestBinInt.cpp"
//#include "UnitTestBinVect.cpp"
//#include "UnitTestBinMat.cpp"
#include "../include/gtest/gtest.h"
//#include "gtest/gtest-all.cc"


#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/math/nbtheory.h"
#include "../../src/lib/lattice/elemparams.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/lattice/ilelement.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/crypto/lwecrypt.h"
#include "../../src/lib/crypto/lwepre.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"
#include "../../src/lib/utils/utilities.h"

/*
#include "binint.h"
#include "binmat.h"
#include "binvect.h"
#include "inttypes.h"
#include "nbtheory.h"
#include "ideals.h"
#include "distrgen.h"
#include "lwecrypt.h"
#include "lwepre.h"
#include "il2n.h"
#include "utilities.h"
*/

using namespace std;
using namespace lbcrypto;

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);
  RUN_ALL_TESTS();

  std::cout << "Press any key to continue..." << std::endl;
  std::cin.get();

  return 0;
}

