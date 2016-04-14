// This is a main() file built to test some Parallel operations in openmp
// D. Cousins

#include <iostream>
#include <fstream>
//#include "utils/inttypes.h"
//#include "math/backend.h"
//#include "math/nbtheory.h"
//#include "math/distrgen.h"
//#include "lattice/elemparams.h"
//#include "lattice/ilparams.h"
//#include "lattice/ildcrtparams.h"
//#include "lattice/ilelement.h"
//#include "crypto/lwecrypt.h"
#include "obfuscate/lweconjunctionobfuscate.h"
#include "obfuscate/lweconjunctionobfuscate.cpp"
//#include "obfuscate/obfuscatelp.h"
#include "time.h"
#include <chrono>
#include "utils/debug.h"
#include <omp.h> //open MP header

using namespace std;
using namespace lbcrypto;
//Todo(dcousins): migrate this to use utils/debug.cpp

typedef std::string String;  //dbc shortcut

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
  
  int array_size = 1000;
  float foo[array_size];

  bool dbg_flag;

  TimeVar t1,t_total; //for TIC TOC
  double time1;
  double timeTotal;

  TIC(t_total);
  TIC(t1);
  
#pragma omp parallel for
  for (int i = 0; i < array_size; ++i) {
    float tmp = i;
    sleep(.1);
    foo[i] = tmp;
  }
  time1 = TOC(t1);
  DEBUG("First computation time: " << "\t" << time1 << " ms");

  for (int i = 0; i < array_size; ++i) {
    cout<< foo[i] <<" ";
  }
  cout<< endl;


  timeTotal = TOC(t_total);
  DEBUG("Total time: " << "\t" << timeTotal << " ms");
  return 0;
}

