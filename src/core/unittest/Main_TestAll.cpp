#include <iostream>

#include "include/gtest/gtest.h"


#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);
  ::testing::GTEST_FLAG(filter) = "-*_VERY_LONG";
  RUN_ALL_TESTS();

  std::cout << "Press any key to continue..." << std::endl;
  std::cin.get();

  return 0;
}
