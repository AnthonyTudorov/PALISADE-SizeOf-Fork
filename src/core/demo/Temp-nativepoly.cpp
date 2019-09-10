/*
 * @file 
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define PROFILE

#include <iostream>
#include <fstream>
#include <limits>
#include <getopt.h>

#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"

typedef std::numeric_limits< double > dbl;

using namespace std;
using namespace lbcrypto;


#include <iterator>

//NativePoly tests
void Run(uint32_t n, size_t count, bool verify_flag);

int main(int argc, char **argv) {

  size_t count = 20000; //#iterations to run
  uint32_t n = 1024; //ring dimension
  bool verify_flag (false); //if true, verify results
  int opt; //option from command line parsing

  string usage_string =
    string("run demo with settings (default value show in parenthesis):\n")+
    string("-c number of executions to average over (20000)\n")+
    string("-n ring length (1024)\n")+
    string("-v verify operations (don't verify)\n")+
    string("\nh prints this message\n");
  
  while ((opt = getopt(argc, argv, "c:b:n:p:vh")) != -1) {
    switch (opt)
      {
      case 'c':
        count = atoi(optarg);
	break;
      case 'n':
        n = atoi(optarg);
	break;
      case 'v':
	verify_flag = true;
	break;
      case 'h':
      default: /* '?' */
	cout<<usage_string<<endl;
	exit(0);
      }
  }
  cout << "\n===========BENCHMARKING FOR NATIVEPOLY===============: " << endl;
  
  cout << "\nThis code benchmarks NTT and component-wise modular "<<endl;
  cout << "multiplication and addition of two vectors of "<<endl;
  cout << "uint64_t integers using the native Poly formulation." << endl;

  Run(n, count, verify_flag);

  return 0;
}

#define PROFILE

void Run(uint32_t n,  size_t count, bool verify_flag) {
  
  // ring dimension n, set m to twice this
  uint32_t m = 2*n;

  // Find First prime under 2^60

  // Find the first prime over 2^60 that matches q mod (2n) = 1
  NativeInteger firstInteger = FirstPrime<NativeInteger>(60, 2 * n);

  // use a new q = q^0 - 2*n*2^20 to search for new primes
  // (that are less than 2^60). [ensures there will be a prime#]
  firstInteger -= (int64_t)(2*n)*((int64_t)(1)<<20);
  NativeInteger modulus = NextPrime<NativeInteger>(firstInteger, 2 * n);

  //set the corresponding root of unity
  NativeInteger root = RootOfUnity<NativeInteger>(2 * n, modulus);

  auto params = shared_ptr<ILParamsImpl<NativeInteger>>(new ILParamsImpl<NativeInteger>(m, modulus, root));

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(root,m,modulus);

  std::cout << "n = " << m / 2 << std::endl;
  std::cout << "log2 q = " << log2(params->GetModulus().ConvertToDouble()) << std::endl;

  NativePoly::DugType dug;

  double timeNTT(0.0);
  double timeAdd(0.0);
  double timeMult(0.0);

	
  for (size_t k=0; k < count; k++) {

    TimeVar t1; //timier

		// Generate two random polynomials
    NativePoly x2a(dug, params, Format::COEFFICIENT);
    NativePoly x2b(dug, params, Format::COEFFICIENT);

    auto x2aOrig = x2a; //save the originals
    auto x2bOrig = x2b; //save the originals
	  
    x2a.SwitchFormat(); // required before homomorphic operations. 

    TIC(t1);
    x2b.SwitchFormat(); //does NTT 
    timeNTT+=TOC_US(t1);

    TIC(t1);
    auto sum = x2a + x2b;
    timeAdd+=TOC_US(t1);

    TIC(t1);
    auto product = x2a*x2b;
    timeMult+=TOC_US(t1);

    if (verify_flag) {
      bool fail(false);
      if (x2a == x2aOrig) { //should be different
	cout<<"verify x2a switch format failed"<<endl;
	fail |= true;
      }
      if (x2b == x2bOrig) { //should be different
	cout<<"verify x2b switch format failed"<<endl;
	fail |= true;
      }

      x2a.SwitchFormat();
      x2b.SwitchFormat();
      if (x2a != x2aOrig) { //should be the same
	cout<<"verify x2a switch format twice failed"<<endl;
	fail |= true;
      }
      if (x2b != x2bOrig) { //should be the same
	cout<<"verify x2a switch format twice failed"<<endl;
	fail |= true;
      }

      if (fail) {
	cout << "failure in iteration "<<k<<endl;
	exit (-1);
      }
	    
    }  
  }


  if (verify_flag) {
    cout << "All iterations verified successfully."<<endl;
  }
	
  //average out the times
  timeNTT = timeNTT/(1000*count);
  timeAdd =  timeAdd/(1000*count); 
  timeMult = timeMult/(1000*count);
	
  cout << "Number iterations:\t" << count << endl;
  cout << "Average NTT time:\t" << timeNTT << " ms" << endl;
  cout << "Average addition time:\t" << timeAdd << " ms" <<  endl;
  cout << "Average multiplication time:\t" << timeMult << " ms" << endl;

}

