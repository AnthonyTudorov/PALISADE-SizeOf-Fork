// This is a main() file built to test modulo multiply operations
// D. Cousins

#include <iostream>
#include <fstream>
#include "../../lib/utils/inttypes.h"
#include "../../lib/math/backend.h"
#if 1
#include "../../lib/math/nbtheory.h"
#include "../../lib/math/distrgen.h"
#include "../../lib/lattice/elemparams.h"
#include "../../lib/lattice/ilparams.h"
#include "../../lib/lattice/ildcrtparams.h"
#include "../../lib/lattice/ilelement.h"
#include "../../lib/crypto/lwecrypt.h"
#include "../../lib/obfuscate/lweconjunctionobfuscate.h"
#include "../../lib/obfuscate/lweconjunctionobfuscate.cpp"
#include "../../lib/obfuscate/obfuscatelp.h"
#endif
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

  bool dbg_flag = 1;

  TimeVar t1,t2,t3,t_total; //for TIC TOC
  double time1;
  double time2;
  double time3;
  double timeTotal;

  BigBinaryInteger a("18446744073709551616");
  BigBinaryInteger b(18446744073709551617);
  BigBinaryInteger q(1023);

  BigBinaryInteger c1;
  BigBinaryInteger c2;
  BigBinaryInteger c3;
  
  TIC(t_total);
  TIC(t1);
  
  c1 = a.Times(b).Mod(q);
  time1 = TOC(t1);

  TIC(t2);
  c2 = a.ModMul(b,q);

  time2 = TOC(t2);
//
//  TIC(t3);
//  c3 = a.ModBarretMul(b,q,mu);
//
//  time3 = TOC(t3);


  DEBUG("First computation time: " << "\t" << time1 << " ms");
  DEBUG("Second computation time: " << "\t" << time2 << " ms");
  //DEBUG("Third computation time: " << "\t" << time3 << " ms");

  cout << "c1: " << c1 << endl;
  cout << "c2: " << c2 << endl;
  //cout << "c3: " << c3 << endl;

  timeTotal = TOC(t_total);
  DEBUG("Total time: " << "\t" << timeTotal << " ms");



  return 0;
}

