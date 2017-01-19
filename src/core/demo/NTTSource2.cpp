// This is a main() file built to test and time NTT operations
// D. Cousins

#define PROFILE //need to define in order to turn on timing

#define TEST3



#include <iostream>
#include <fstream>
#include "utils/inttypes.h"
#include "math/backend.h"
#if 1
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
//#include/crypto/lwecrypt.h"
#include "obfuscation/lweconjunctionobfuscate.h"
#include "obfuscation/lweconjunctionobfuscate.cpp"
#include "obfuscation/obfuscatelp.h"
#endif
#include "time.h"
#include <chrono>
#include <exception>
#include "utils/debug.h"
#include <omp.h> //open MP header

using namespace std;
using namespace lbcrypto;

//define the main sections of the test
void test_NTT(void); 	// test code

//main()   need this for Kurts' makefile to ignore this.
int main(int argc, char* argv[]){
  test_NTT();
  return 0;
}

//function to compare two BigBinaryVectors and print differing indicies
void vec_diff(BigBinaryVector &a, BigBinaryVector &b) {
  for (usint i= 0; i < a.GetLength(); ++i){  
    if (a.GetValAtIndex(i) != b.GetValAtIndex(i)) {
      cout << "i: "<< i << endl;
      cout << "first vector " <<endl;
      cout << a.GetValAtIndex(i);
      cout << endl;
      cout << "second vector " <<endl;
      cout << b.GetValAtIndex(i);
      cout << endl;

    }
  }

}

//function to compare two ILVector2n and print differing values
bool clonetest(ILVector2n &a, ILVector2n &b, string name){ 
  if (a != b){
    cout << name <<" FAILED "<<endl;
    return true;
  } else {
    return false;
  }
}

//main NTT test suite.
void test_NTT () {
  // Code to test NTT at three different numbers of limbs.

  int nloop = 10; //number of times to run each test for timing.
  bool dbg_flag = 1;		// if true then print dbg output
 
  TimeVar t1,t2, t3,t_total; // timers for TIC() TOC()
  // captures the time
  double time1ar, time1af;
  double time2ar, time2af;
  double time3ar, time3af;

  double time1br, time1bf;
  double time2br, time2bf;
  double time3br, time3bf;

  cout<<"testing NTT backend "<<MATHBACKEND;
  if (BigBinaryIntegerBitLength >0)
    cout<<" BITLENGTH "<< BigBinaryIntegerBitLength;
  cout <<endl;

  TIC(t_total);

  BigBinaryInteger q1 ("270337"); //test case 1 smaller than 32 bits
  BigBinaryInteger q2 ("4503599627446273");   //test case 2 32 > x> 64 bits

  usint m = 2048;
  cout << "m=" << m << endl;

  BigBinaryInteger rootOfUnity1(RootOfUnity(m, q1));
  cout << "q1 = " << q1 << endl;
  cout << "rootOfUnity1 = " << rootOfUnity1 << endl;

  //build parameters fo`r two vectors. 
  ILParams params1(m, q1, rootOfUnity1);
  shared_ptr<ILParams> x1p(new ILParams(params1));

  const DiscreteUniformGenerator dug1(q1); //random # generator to use

  // two vectors
  ILVector2n x1a(dug1, x1p, Format::COEFFICIENT); 
  ILVector2n x1b(dug1, x1p, Format::COEFFICIENT);


  for (size_t ix = 0; ix < m/2; ix++){
    if (x1a.GetValues().GetValAtIndex(ix)>=q1) {
      cout<<"bad value x1a "<<endl;
    }
    if (x1b.GetValues().GetValAtIndex(ix)>=q1) {
      cout<<"bad value x1a "<<endl;
    }
  }
  //make copies to compare against
  ILVector2n x1aClone(x1a);
  ILVector2n x1bClone(x1b);

  //repeat for q2;
  BigBinaryInteger rootOfUnity2(RootOfUnity(m, q2));
  cout << "q2 = " << q2 << endl;
  cout << "rootOfUnity2 = " << rootOfUnity2 << endl;

  ILParams params2(m, q2, rootOfUnity2);
  shared_ptr<ILParams> x2p(new ILParams(params2));

  const DiscreteUniformGenerator dug2(q2);

  ILVector2n x2a(dug2, x2p, Format::COEFFICIENT);
  ILVector2n x2b(dug2, x2p, Format::COEFFICIENT);

  ILVector2n x2aClone(x2a);
  ILVector2n x2bClone(x2b);

#ifdef TEST3
  //repeat for q3
  //note computation of root of unity for big numbers takes forever
  //hardwire this case
  BigBinaryInteger q3("13093562431584567480052758787310396608866568184172259157933165472384535185618698219533080369303616628603546736510240284036869026183541572213314110873601");

  BigBinaryInteger rootOfUnity3("12023848463855649466660377440069556144464267030949365165993725942220441412632799311989973938254823071405336623315668961501139592673000297887682895033094");

  cout << "q3 : "<<q3.ToString()<<endl;
  cout << "rootOfUnity3 : "<<rootOfUnity3.ToString()<<endl;

  ILParams params3(m, q3, rootOfUnity3);
  shared_ptr<ILParams> x3p(new ILParams(params3));

  const DiscreteUniformGenerator dug3(q3); //random # generator to use

  // two vectors
  ILVector2n x3a(dug3, x3p, Format::COEFFICIENT); 
  ILVector2n x3b(dug3, x3p, Format::COEFFICIENT);

  //make copies to compare against
  ILVector2n x3aClone(x3a);
  ILVector2n x3bClone(x3b);
#endif

  //Precomputations for FTT
  ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity1, m, q1);
  ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity2, m, q2);
#ifdef TEST3
  ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity3, m, q3);
#endif

  time1af = 0.0;
  time1bf = 0.0;

  time2af = 0.0;
  time2bf = 0.0;

  time3af = 0.0;
  time3bf = 0.0;

  time1ar = 0.0;
  time1br = 0.0;

  time2ar = 0.0;
  time2br = 0.0;

  time3ar = 0.0;
  time3br = 0.0;


  bool failed = false;
  usint ix;
  cout << "Startng timing"<<endl;

  for (ix = 0; ix <nloop; ix++) {
    if (ix%100 == 0)
      cout << ix <<endl;
    
    //forward 
    TIC(t1);
    x1a.SwitchFormat();
    time1af += TOC_US(t1);

    TIC(t1);
    x1b.SwitchFormat();
    time1bf += TOC_US(t1);

    TIC(t1);
    x2a.SwitchFormat();
    time2af += TOC_US(t1);

    TIC(t1);
    x2b.SwitchFormat();
    time2bf += TOC_US(t1);

#ifdef TEST3
    TIC(t1);
    x3a.SwitchFormat();
    time3af += TOC_US(t1);

    TIC(t1);
    x3b.SwitchFormat();
    time3bf += TOC_US(t1);
#endif

    //reverse
    TIC(t1);
    x1a.SwitchFormat();
    time1ar += TOC_US(t1);

    TIC(t1);
    x1b.SwitchFormat();
    time1br += TOC_US(t1);

    TIC(t1);
    x2a.SwitchFormat();
    time2ar += TOC_US(t1);

    TIC(t1);
    x2b.SwitchFormat();
    time2br += TOC_US(t1);

#ifdef TEST3
    TIC(t1);
    x3a.SwitchFormat();
    time3ar += TOC_US(t1);

    TIC(t1);
    x3b.SwitchFormat();
    time3br += TOC_US(t1);
#endif

    failed |= clonetest(x1a, x1aClone, "x1a");
    failed |= clonetest(x1b, x1bClone, "x1b");
    failed |= clonetest(x2a, x2aClone, "x2a");
    failed |= clonetest(x2b, x2bClone, "x2b");
#ifdef TEST3
    failed |= clonetest(x3a, x3aClone, "x3a");
    failed |= clonetest(x3b, x3bClone, "x3b");
#endif

  }

  if (failed) {
    cout << "failure in loop number "<< ix<<endl;
  } else {
    
    time1af/=(double)nloop;
    time1bf/=(double)nloop;
    time2af/=(double)nloop;
    time2bf/=(double)nloop;
    time3af/=(double)nloop;
    time3bf/=(double)nloop;
    
    time1ar/=(double)nloop;
    time1br/=(double)nloop;
    time2ar/=(double)nloop;
    time2br/=(double)nloop;
    time3ar/=(double)nloop;
    time3br/=(double)nloop;
    
    
    cout << nloop << " loops"<<endl;
    cout << "t1af: "  << "\t" << time1af << " us"<< endl;
    cout << "t1bf: " << "\t" << time1bf << " us"<< endl;
    
    cout << "t2af: " << "\t" << time2af << " us"<< endl;
    cout << "t2bf: " << "\t" << time2bf << " us"<< endl;
    
    cout << "t3af: " << "\t" << time3af << " us"<< endl;
    cout << "t3bf: " << "\t" << time3bf << " us"<< endl;

    cout << "t1ar: " << "\t" << time1ar << " us"<< endl;
    cout << "t1br: " << "\t" << time1br << " us"<< endl;
    
    cout << "t2ar: " << "\t" << time2ar << " us"<< endl;
    cout << "t2br: " << "\t" << time2br << " us"<< endl;
    
    cout << "t3ar: " << "\t" << time3ar << " us"<< endl;
    cout << "t3br: " << "\t" << time3br << " us"<< endl;
  }
  
  return ;
}


