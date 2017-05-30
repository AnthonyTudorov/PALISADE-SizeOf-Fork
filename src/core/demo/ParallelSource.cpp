// This is a main() file built to test some Parallel operations in openmp
// D. Cousins

#include <iostream>
#include <fstream>
#include "obfuscation/lweconjunctionobfuscatev3.h"
#include "obfuscation/lweconjunctionobfuscatev3.cpp"
#include "time.h"
#include <chrono>
#include "utils/debug.h"
#include <omp.h> //open MP header

//using namespace std;
using namespace lbcrypto;

const uint32_t ARRAY_SIZE = 1000;

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
  
  //int array_size = 1000;
  //non-const array is size is not supported in MVC; only in GCC; this is why the const was introduced
  //float foo[array_size];
  float foo[ARRAY_SIZE];

  bool dbg_flag = false;

  TimeVar t1,t_total; //for TIC TOC
  double time1;
  double timeTotal;

  std::cout << "Parallel computation using "<< omp_get_num_procs() << " processors." <<std::endl;
  int nthreads, tid;
  #pragma omp parallel private(nthreads, tid)
  {
    
    /* Obtain thread number */
    tid = omp_get_thread_num();
    
    /* Only master thread does this */
    if (tid == 0)
      {
	nthreads = omp_get_num_threads();
	std::cout << "Number of threads = " << nthreads << std::endl;
      }
  }

  
  TIC(t_total);
  TIC(t1);
  
#pragma omp parallel for
  for (size_t i = 0; i < ARRAY_SIZE; ++i) {
    float tmp = i;

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    foo[i] = tmp;
  }
  time1 = TOC(t1);
  DEBUG("First computation time: " << "\t" << time1 << " ms");

  timeTotal = TOC(t_total);
  DEBUG("Total time: " << "\t" << timeTotal << " ms");

  bool goodflag = true;
  for (size_t i = 1; i < ARRAY_SIZE; ++i) {
    if ((foo[i]-foo[i-1])!= 1) {
      goodflag = goodflag & false;
    }
  }
  if ( goodflag) {
      std::cout << "success" << std::endl;
  } else {
    std::cout<< "fail" << std::endl;
    for (size_t i = 0; i < ARRAY_SIZE; ++i) {
      std::cout << foo[i] << " ";
    }
    std::cout << std::endl;
  }


  return 0;
}

