/*
 * @file 
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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

#include <iostream>
#include <fstream>
#include <limits>
#include <cmath>
#include <getopt.h>

#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;

#include "../../core/lib/lattice/poly.cpp"
#include "../../core/lib/lattice/dcrtpoly.cpp"
#include "../../core/lib/lattice/ildcrtparams.cpp"

#include <iterator>

namespace lbcrypto {
#ifdef WITH_NATIVE64
template class DCRTPolyImpl<BigVector, NativePoly64>;
template class ILDCRTParams<BigInteger, NativeInteger64>;
template<>
PolyImpl<NativeVector64,NativeVector64>
PolyImpl<NativeVector64,NativeVector64>::ToNativePoly() const {
	return *this;
}
#endif

#ifdef WITH_NATIVE32
template class DCRTPolyImpl<BigVector, NativePoly32>;
template class ILDCRTParams<BigInteger, NativeInteger32>;
template<>
PolyImpl<NativeVector32,NativeVector32>
PolyImpl<NativeVector32,NativeVector32>::ToNativePoly() const {
	return *this;
}
#endif

#ifdef WITH_NATIVE16
template class DCRTPolyImpl<BigVector, NativePoly16>;
template class ILDCRTParams<BigInteger, NativeInteger16>;
template<>
PolyImpl<NativeVector16,NativeVector16>
PolyImpl<NativeVector16,NativeVector16>::ToNativePoly() const {
	return *this;
}
#endif
}

//Poly tests
template<typename DCRT>
void Run(uint32_t mode, uint32_t n, size_t count, int n_threads, bool verify_flag, bool oneline, int size);

int main(int argc, char **argv) {

  size_t count = 20000; //#iterations to run
  uint32_t mode = 120; //# bits of modulus
  int size = 64; // size of native int
  int n_threads = 0; //0 means use default number
  uint32_t n = 1024; //ring dimension
  bool verify_flag (false); //if true, verify results
  bool oneline(false);
  int opt; //option from command line parsing

  string usage_string =
    string("run bfvrns demo with settings (default value show in parenthesis):\n")+
    string("-c number of executions to average over (20000)\n")+
    string("-b number bits  30|60|120|240|480 (120)\n")+
    string("-n ring length (1024)\n")+
    string("-p number of parallel threads (up to system max)\n")+
    string("-v verify operations (don't verify)\n")+
	string("-s size of integer 16|32|64 (64)\n")+
	string("-l print all output on a single line")+
    string("\nh prints this message\n");

  while ((opt = getopt(argc, argv, "c:b:n:p:s:lvh")) != -1) {
	  switch (opt)
	  {
	  case 'c':
		  count = atoi(optarg);
		  break;
	  case 'b':
		  mode = atoi(optarg);
		  if (!((mode == 30)||(mode == 60)||(mode == 120)||(mode == 240)||(mode == 480))) {
			  cout << "mode must be one of 30, 60, 120, 240 or 480"<<endl;
			  exit(-1);
		  }
		  break;
	  case 's':
		  size = atoi(optarg);
		  if (!((size == 16)||(size == 32)||(size == 64))) {
			  cout << "size must be one of 16, 32, 64"<<endl;
			  exit(-1);
		  }
		  break;
	  case 'n':
		  n = atoi(optarg);
		  break;
	  case 'p':
		  n_threads = atoi(optarg);
		  break;
	  case 'v':
		  verify_flag = true;
		  break;
	  case 'l':
		  oneline = true;
		  break;
	  case 'h':
	  default: /* '?' */
		  cout<<usage_string<<endl;
		  exit(0);
	  }
  }
  
  if( !oneline ) {
	  cout << "\n===========BENCHMARKING FOR DCRTPOLY===============: " << endl;

	  cout << "\nThis code benchmarks NTT and component-wise modular "<<endl;
	  cout << "multiplication and addition of two vectors of "<<endl;
	  cout << "multiprecision integers using the double crt Poly formulation." << endl;
  }

  Run<DCRTPolyImpl<BigVector>>(mode, n, count, n_threads, verify_flag, oneline, size);

  return 0;
}

#define PROFILE

template<typename DCRT>
void Run(uint32_t mode, uint32_t n,  size_t count, int n_threads, bool verify_flag, bool oneline, int size) {

  //
  auto nbits = 64;
  auto qbits = nbits - 4;

  //set the number of threads to use when running. 
  if (n_threads != 0) { // note it is set to zero as the default
    PalisadeParallelControls.SetNumThreads(n_threads);
  }
	
  // ring dimension n, set m to twice this
  uint32_t m = 2*n;

  uint32_t limbs = mode/qbits;

  vector<typename DCRT::PolyType::Integer> moduli(limbs);
  vector<typename DCRT::PolyType::Integer> roots(limbs);

  // First prime close to largest available...

  // Find the first prime that matches q mod (2n) = 1
  typename DCRT::PolyType::Integer firstInteger = FirstPrime<typename DCRT::PolyType::Integer>(qbits, 2 * n);

  // use a new q = q^0 - 2*n*2^(qbits/3) to search for new primes
  // [ensures there will be a prime#]
  firstInteger -= (int64_t)(2*n)*((int64_t)(1)<<(qbits/3));
  moduli[0] = NextPrime<typename DCRT::PolyType::Integer>(firstInteger, 2 * n);
  //set the corresponding root of unity
  roots[0] = RootOfUnity<typename DCRT::PolyType::Integer>(2 * n, moduli[0]);

  for (size_t i = 1; i < limbs; i++)
    {
      moduli[i] = PreviousPrime<typename DCRT::PolyType::Integer>(moduli[i-1], m);
      roots[i] = RootOfUnity<typename DCRT::PolyType::Integer>(m, moduli[i]);
    }

  auto params = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(m, moduli, roots));

  ChineseRemainderTransformFTT<typename DCRT::PolyType::Vector>::PreCompute(roots,m,moduli);

  typename DCRT::DugType dug;

  double timeNTT(0.0), timeNTTss(0.0);
  double timeAdd(0.0), timeAddss(0.0);
  double timeMult(0.0), timeMultss(0.0);
	
  for (size_t k=0; k < count; k++) {

    TimeVar t1; //timer

		// Generate two random polynomials
    DCRT x2a(dug, params, Format::COEFFICIENT);
    DCRT x2b(dug, params, Format::COEFFICIENT);
    DCRT sum, product;

    //verify that the number of towers is what we think it is.
    usint ntower = x2a.GetNumOfElements();
    if (ntower != limbs) {
      cout << "limbs "<< limbs<< " ntower "<<ntower<<endl;
      exit(-1);
    }
    auto x2aOrig = x2a; //save the originals
    auto x2bOrig = x2b; //save the originals

    x2a.SwitchFormat(); // required before homomorphic operations. 

    double sftoc(0.0);
    {
    TIC(t1);
    x2b.SwitchFormat(); //does NTT
    sftoc = TOC_US(t1);
    }

    timeNTT+=sftoc;
    timeNTTss+=sftoc*sftoc;

    double addtoc(0.0);
    {
    TIC(t1);
    sum = x2a + x2b;
    addtoc = TOC_US(t1);
    }
    timeAdd+=addtoc;
    timeAddss+=addtoc*addtoc;

    bool fail(false);
    if (verify_flag) {
    	auto bigsum = x2a.CRTInterpolate() + x2b.CRTInterpolate();
    	if( sum.CRTInterpolate() != bigsum ) {
    		cout<<"verify addition failed"<<endl;
    		fail|=true;
    	}
    }

    double multoc(0.0);
    {
    TIC(t1);
    product = x2a*x2b;
    multoc = TOC_US(t1);
    }
    timeMult+=multoc;
    timeMultss+=multoc*multoc;

    if (verify_flag) {
    	auto bigprod = x2a.CRTInterpolate() * x2b.CRTInterpolate();
    	if( product.CRTInterpolate() != bigprod ) {
    		cout<<"verify multiplication failed"<<endl;
    		fail|=true;
    	}

      if (x2a == x2aOrig) { //should be different
		cout<<"verify x2a switch format failed"<<endl;
		fail |= true;
      }
      if (x2b == x2bOrig) { //should be different
		cout<<"verify x2b switch format failed"<<endl;
		fail |= true;
      }

      x2a.SwitchFormat();
#if 0
	  x2b.SwitchFormat();
#endif
	  if (x2a != x2aOrig) { //should be the same
		cout<<"verify x2a switch format twice failed"<<endl;
		fail |= true;
	  }
#if 0 
      if (x2b != x2bOrig) { //should be the same
		cout<<"verify x2a switch format twice failed"<<endl;
		fail |= true;
      }
#endif	  
      if (fail) {
		cout << "failure in iteration "<<k<<endl;
		exit (-1);
      }
    }  
  }

  auto timeNTTsd = sqrt((count*timeNTTss) - (timeNTT*timeNTT))/count;
  auto timeAddsd =  sqrt((count*timeAddss) - (timeAdd*timeAdd))/count;
  auto timeMultsd = sqrt((count*timeMultss) - (timeMult*timeMult))/count;
	
  if( oneline ) {
	  cout << "threads,s,n,ntower,log2q,c,nttav,nttsd,nttsdpct,addav,addsd,addsdpct,mulav,mulsd,mulsdpct" << endl;
	  cout << PalisadeParallelControls.GetNumThreads() << ",";
	  cout << size << ",";
	  cout << m / 2 << ",";
	  cout << limbs << ",";
	  cout << log2(params->GetModulus().ConvertToDouble()) << ",";

	  cout << count << ",";
	  cout << timeNTT/count << "," << timeNTTsd << "," << (timeNTTsd/(timeNTT/count))*100 << ",";
	  cout << timeAdd/count << "," << timeAddsd << "," << (timeAddsd/(timeAdd/count))*100 << ",";
	  cout << timeMult/count << "," << timeMultsd << "," << (timeMultsd/(timeMult/count))*100 << endl;
	  return;
  }
  cout << "\nNumber of threads = "
       << PalisadeParallelControls.GetNumThreads() << endl;
  cout << "Native size = " << size << endl;
  std::cout << "n = " << m / 2 << std::endl;
  std::cout << "tower size = " << limbs << std::endl;
  std::cout << "log2 q = " << log2(params->GetModulus().ConvertToDouble()) << std::endl;

  cout << "Number iterations:\t" << count << endl;
  cout << "Average NTT time:\t" << timeNTT/count << " us, stdev " << timeNTTsd << " " << (timeNTTsd/(timeNTT/count))*100 << "%" << endl;
  cout << "Average addition time:\t" << timeAdd/count << " us, stdev " << timeAddsd << " " << (timeAddsd/(timeAdd/count))*100 << "%"<<  endl;
  cout << "Average multiplication time:\t" << timeMult/count << " us, stdev " << timeMultsd << " " << (timeMultsd/(timeMult/count))*100 << "%"<< endl;

}

