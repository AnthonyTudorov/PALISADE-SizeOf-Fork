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

double currentDateTime()
{

	std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

    time_t tnow = std::chrono::system_clock::to_time_t(now);
    tm *date = localtime(&tnow);
    date->tm_hour = 0;
    date->tm_min = 0;
    date->tm_sec = 0;

    auto midnight = std::chrono::system_clock::from_time_t(mktime(date));

	return std::chrono::duration <double, std::milli>(now - midnight).count();
}

typedef std::chrono::high_resolution_clock::time_point TimeVar;

#define duration(a) std::chrono::duration_cast<std::chrono::milliseconds>(a).count()
#define timeNow() std::chrono::high_resolution_clock::now()

template<typename F, typename... Args>
double funcTime(F func, Args&&... args){
    TimeVar t1=timeNow();
    func(std::forward<Args>(args)...);
    return duration(timeNow()-t1);
}

#define TIC t1=timeNow() 
#define TOC duration(timeNow()-t1)

#define TOTAL_TIC t2=timeNow() 
#define TOTAL_TOC duration(timeNow()-t2)


typedef std::string String;  //dbc shortcut

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
  
  int array_size = 1000;
  float foo[array_size];

  
#pragma omp parallel for
  for (int i = 0; i < array_size; ++i) {

    float tmp = i;
        sleep(.1);
    foo[i] = tmp;

    //cout << i <<" ";
  }

  cout <<endl;
  for (int i = 0; i < array_size; ++i) {
    cout<< foo[i] <<" ";
  }

  cout<< endl;

  
  return 0;
}

