#ifndef LBCRYPTO_MATH_CAPSUTILS_H
#define LBCRYPTO_MATH_CAPSUTILS_H
#include <assert.h>
#include <stdlib.h>

namespace lbcrypto {

struct MatDescriptor {
  int lda;
  int nrec;
  int nproc;
  int nprocr;
  int nprocc;
  int nproc_summa;
  int bs;
};

const int DESC_SIZE = 7; // number of ints that make up a MatDescriptor
const int rank=0,  base=0;



int getRank();
void verifyDescriptor( MatDescriptor desc );
long long numEntriesPerProc( MatDescriptor desc );
}
#endif
