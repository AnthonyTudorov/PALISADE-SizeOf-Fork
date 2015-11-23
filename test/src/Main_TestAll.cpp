//#include "UnitTestBinInt.cpp"
//#include "UnitTestBinVect.cpp"
//#include "UnitTestBinMat.cpp"
#include "../include/gtest/gtest.h"
//#include "gtest/gtest-all.cc"

#include "../../src/math/backend.h"
#include "../../src/utils/inttypes.h"
#include "../../src/math/nbtheory.h"
#include "../../src/lattice/ideals.h"
#include "../../src/math/distrgen.h"
#include "../../src/crypto/lwecrypt.h"
#include "../../src/crypto/lwepre.h"
#include "../../src/lattice/il2n.h"
#include "../../src/utils/utilities.h"

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
  return RUN_ALL_TESTS();
}

