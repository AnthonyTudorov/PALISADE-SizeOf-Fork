// This is a main() file built to test some Parallel operations in openmp
// D. Cousins

#include <iostream>
#include <fstream>
//#include "../../lib/utils/inttypes.h"
//#include "../../lib/math/backend.h"
//#include "../../lib/math/nbtheory.h"
//#include "../../lib/math/distrgen.h"
//#include "../../lib/lattice/elemparams.h"
//#include "../../lib/lattice/ilparams.h"
//#include "../../lib/lattice/ildcrtparams.h"
//#include "../../lib/lattice/ilelement.h"
//#include "../../lib/crypto/lwecrypt.h"
#include "../../lib/obfuscate/lweconjunctionobfuscate.h"
#include "../../lib/obfuscate/lweconjunctionobfuscate.cpp"
//#include "../../lib/obfuscate/obfuscatelp.h"
#include "time.h"
#include <chrono>
#include "../../lib/utils/debug.h"
#include <omp.h> //open MP header

using namespace std;
using namespace lbcrypto;

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
  
  int array_size = 1000;
  float foo[array_size];

  bool dbg_flag;

  TimeVar t1,t_total; //for TIC TOC
  double time1;
  double timeTotal;

  cout << "Parallel computation using "<< omp_get_num_procs() << " processors." <<endl;
  int nthreads, tid;
  #pragma omp parallel private(nthreads, tid)
  {
    
    /* Obtain thread number */
    tid = omp_get_thread_num();
    
    /* Only master thread does this */
    if (tid == 0)
      {
	nthreads = omp_get_num_threads();
	cout << "Number of threads = " << nthreads << endl;
      }
  }

  
  TIC(t_total);
  TIC(t1);
  
#pragma omp parallel for
  for (int i = 0; i < array_size; ++i) {
    float tmp = i;

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    foo[i] = tmp;
  }
  time1 = TOC(t1);
  DEBUG("First computation time: " << "\t" << time1 << " ms");

  timeTotal = TOC(t_total);
  DEBUG("Total time: " << "\t" << timeTotal << " ms");

  bool goodflag = true;
  for (int i = 1; i < array_size; ++i) {
    if ((foo[i]-foo[i-1])!= 1) {
      goodflag = goodflag & false;
    }
  }
  if ( goodflag) {
      cout << "success" << endl;
  } else {
    cout<< "fail" << endl;
    for (int i = 0; i < array_size; ++i) {
      cout << foo[i] << " ";
    }
    cout << endl;
  }


  return 0;
}

