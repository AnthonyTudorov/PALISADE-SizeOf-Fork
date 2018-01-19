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

#define PROFILE  //define this to enable PROFILELOG and TIC/TOC 
// Note must must be before all headers

#include <iostream>
#include <fstream>
#include "obfuscation/lweconjunctionobfuscate.h"
#include "obfuscation/lweconjunctionobfuscate.cpp"

#include "utils/debug.h"

#include <omp.h> //open MP header TODO Delete

using namespace lbcrypto;

bool EvaluateConjObfs(bool dbg_flag, int  n); //defined later

void  DeserializeClearPatternFromFile(const string clearFileName,
				      ClearLWEConjunctionPattern<DCRTPoly> &clearPattern);
void  DeserializeObfuscatedPatternFromFile(const string obfFileName, ObfuscatedLWEConjunctionPattern<DCRTPoly> &obsPattern);

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
  
  
  if (argc < 2) { // called with no arguments
    std::cout << "arg 1 = debugflag 0:1 [0] " << std::endl;
    std::cout << "arg 2 = num bits [8] >7 <14 " << std::endl;
  }
  bool dbg_flag = false; 

  if (argc >= 2 ) {
    if (atoi(argv[1]) != 0) {
      dbg_flag = true;
      std::cout << "setting dbg_flag true" << std::endl;
    }
  }
  int n_bits = 8;

  if (argc >= 3 ) { 
    if (atoi(argv[2]) < 8) {
      n_bits = 8;
    } else if (atoi(argv[2]) >= 13) {
      n_bits = 13;
    } else {
      n_bits = atoi(argv[2]);
    }
  }
  

  
  DEBUG("DEBUG IS TRUE");
  PROFILELOG("PROFILELOG IS TRUE");
#ifdef PROFILE
  std::cout << "PROFILE is defined" << std::endl;
#endif
#ifdef NDEBUG
  std::cout << "NDEBUG is defined" << std::endl;
#endif
  
  std::cerr << "Running " << argv[0] << " with "
	    << n_bits << " bits." << std::endl;
  
  
  //determine #processors and # threads for run
  int nthreads, tid;
  std::cerr  <<"Running " << argv[0] <<" with "
	     << omp_get_num_procs() << " processors and ";
  
  // Fork a team of threads giving them their own copies of variables
  //so we can see how many threads we have to work with
#pragma omp parallel private(nthreads, tid)
  {
    
    /* Obtain thread number */
    tid = omp_get_thread_num();

    /* Only master thread does this */
    if (tid == 0)
      {
	nthreads = omp_get_num_threads();
	std::cout << nthreads << std::endl;
      }
  }
    
  bool errorflag = false;
  unsigned int n = 1<<n_bits;
  errorflag = EvaluateConjObfs(dbg_flag, n);
  return ((int)errorflag);

}


//////////////////////////////////////////////////////////////////////
bool EvaluateConjObfs(bool dbg_flag, int n) {

  //if dbg_flag == true; print debug outputs
  // n = size of vectors to use

  //returns
  //  errorflag = 1 if fail


  TimeVar t1, t_total; //for TIC TOC
  TIC(t_total); //start timer for total time

  usint m = 2*n;

  //usint chunkSize = 8;
  //  usint base = 1<<20;

  //if (n > 1<<10)
  //base = 1<<15;

  //Read the test pattern from the file
  ClearLWEConjunctionPattern<DCRTPoly> clearPattern("");
  string clearFileName = "cp"+to_string(n);
  DEBUG("reading clearPattern from file: "<<clearFileName<<".json");
  DeserializeClearPatternFromFile(clearFileName, clearPattern);

  LWEConjunctionObfuscationAlgorithm<DCRTPoly> algorithm;
    
#if 0  

  ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern;
  obfuscatedPattern.SetChunkSize(chunkSize);
  obfuscatedPattern.SetBase(base);
  obfuscatedPattern.SetLength(clearPattern.GetLength());
  obfuscatedPattern.SetRootHermiteFactor(1.006);


  //Variables for timing
  double timeDGGSetup(0.0), timeKeyGen(0.0), timeObf(0.0), timeEval1(0.0),
    timeEval2(0.0), timeEval3(0.0), timeTotal(0.0);

  double stdDev = SIGMA;
  DCRTPoly::DggType dgg(stdDev);			// Create the noise generator

  //Finds q using the correctness constraint for the given value of n
  algorithm.ParamsGen(dgg, &obfuscatedPattern, m / 2);

  //this code finds the values of q and n corresponding to the root Hermite factor in obfuscatedPattern
  //algorithm.ParamsGen(dgg, &obfuscatedPattern);

  const shared_ptr<typename DCRTPoly::Params> ilParams = obfuscatedPattern.GetParameters();

  const BigInteger &modulus = ilParams->GetModulus();
  const BigInteger &rootOfUnity = ilParams->GetRootOfUnity();

  PROFILELOG("\nq = " << modulus);
  PROFILELOG("rootOfUnity = " << rootOfUnity);
  PROFILELOG("n = " << m / 2);
  PROFILELOG(printf("delta=%lf", obfuscatedPattern.GetRootHermiteFactor()));
  PROFILELOG("\nbase = " << base);

  typename DCRTPoly::DugType dug;
  typename DCRTPoly::TugType tug;

  PROFILELOG("\nCryptosystem initialization: Performing precomputations...");

  //This code is run only when performing execution time measurements
#endif


  //Variables for timing
  //todo make eval an array
  double timeEval1(0.0), timeEval2(0.0), timeEval3(0.0), timeTotal(0.0);


  string obfFileName = "op"+to_string(n);
  //note this is for debug -- will move to evaluate program once it all works
  ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern;

  DeserializeObfuscatedPatternFromFile(obfFileName, obfuscatedPattern);

  const shared_ptr<typename DCRTPoly::Params> ilParams = obfuscatedPattern.GetParameters();
  m = ilParams->GetCyclotomicOrder();
  
  double stdDev = SIGMA;
  DCRTPoly::DggType dgg(stdDev);			// Create the noise generator

  //Finds q using the correctness constraint for the given value of n
  algorithm.ParamsGen(dgg, &obfuscatedPattern, m / 2);
  
  //Precomputations for FTT
  DiscreteFourierTransform::PreComputeTable(m);


  ////////////////////////////////////////////////////////////
  //Test the cleartext pattern
  ////////////////////////////////////////////////////////////

  DEBUG(" \nCleartext pattern: ");
  DEBUG(clearPattern.GetPatternString());

  DEBUG(" \nCleartext pattern length: ");
  DEBUG(clearPattern.GetLength());

  //std::string inputStr1 = "1110010011100100111001001110010011100100111001001110010011100100";
  std::string inputStr1 = "11100100";
  bool out1 = algorithm.Evaluate(clearPattern, inputStr1);
  DEBUG(" \nCleartext pattern evaluation of: " << inputStr1 << " is " << out1);
  
  //std::string inputStr2 = "1100110111001101110011011100111111001101110011011100110111001111";
  std::string inputStr2 = "11001101";
  bool out2 = algorithm.Evaluate(clearPattern, inputStr2);
  DEBUG(" \nCleartext pattern evaluation of: " << inputStr2 << " is " << out2);
  
  //std::string inputStr3 = "1010110110101101101011011010110110101101101011011010110110101101";
  std::string inputStr3 = "10101101";
  bool out3 = algorithm.Evaluate(clearPattern, inputStr3);
  DEBUG(" \nCleartext pattern evaluation of: " << inputStr3 << " is " << out3);
	
  ////////////////////////////////////////////////////////////
  //Generate and test the obfuscated pattern
  ////////////////////////////////////////////////////////////

  //todo make this a loop
  bool result1 = false;
  bool result2 = false;
  bool result3 = false;
  std::cout << " \nCleartext pattern: " << std::endl;
  std::cout << clearPattern.GetPatternString() << std::endl;

  PROFILELOG("Evaluation started");
  TIC(t1);
  result1 = algorithm.Evaluate(obfuscatedPattern, inputStr1);
  timeEval1 = TOC(t1);
  DEBUG(" \nCleartext pattern evaluation of: " << inputStr1 << " is " << result1 << ".");
  PROFILELOG("Evaluation 1 execution time: " << "\t" << timeEval1 << " ms");

  usint n_evals = 3;
  
  bool errorflag = false;
  if (result1 != out1) {
    std::cout << "ERROR EVALUATING 1 "<<" got "<<result1<<" wanted "<<out1<< std::endl;
    errorflag |= true;
  }
  if (n_evals > 1) {
    PROFILELOG("Evaluation 2 started");
    TIC(t1);
    result2 = algorithm.Evaluate(obfuscatedPattern, inputStr2);
    timeEval2 = TOC(t1);
    DEBUG(" \nCleartext pattern evaluation of: " << inputStr2 << " is " << result2 << ".");
    PROFILELOG("Evaluation 2 execution time: " << "\t" << timeEval2 << " ms");

    if (result2 != out2) {
      std::cout << "ERROR EVALUATING 2"<<" got "<<result2<<" wanted "<<out2 << std::endl;
      errorflag |= true;
    }
  }

  if (n_evals > 2) {
    PROFILELOG("Evaluation 3 started");
    TIC(t1);
    result3 = algorithm.Evaluate(obfuscatedPattern, inputStr3);
    timeEval3 = TOC(t1);
    DEBUG("\nCleartext pattern evaluation of: " << inputStr3 << " is " << result3 << ".");
    PROFILELOG("Evaluation 3 execution time: " << "\t" << timeEval3 << " ms");
    if (result3 != out3) {
      std::cout << "ERROR EVALUATING 3" <<" got "<<result3<<" wanted "<<out3 << std::endl;
      errorflag |= true;
    }
  }

  //get the total program run time.
  timeTotal = TOC(t_total);

  //print output timing results
  //note one could use PROFILELOG for these lines
  std::cout << "Timing Summary for n = " << m / 2 << std::endl;
  std::cout << "T: Eval 1 execution time:  " << "\t" << timeEval1 << " ms" << std::endl;
  std::cout << "T: Eval 2 execution time:  " << "\t" << timeEval2 << " ms" << std::endl;
  std::cout << "T: Eval 3 execution time:  " << "\t" << timeEval3 << " ms" << std::endl;
  std::cout << "T: Average evaluation execution time:  " << "\t" << (timeEval1+timeEval2+timeEval3)/3 << " ms" << std::endl;
  std::cout << "T: Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

  if (errorflag) {
    std::cout << "FAIL " << std::endl;
  }
  else {
    std::cout << "SUCCESS " << std::endl;
  }

  DiscreteFourierTransform::Reset();
  
  return (errorflag);
}


//////////////////////////////////////////////////////////////
void  DeserializeClearPatternFromFile(const string clearFileName, ClearLWEConjunctionPattern<DCRTPoly> &clearPattern){

  bool dbg_flag = false;
  DEBUG("in DeserializeClearPatternFromFile");

  Serialized serObj;
  serObj.SetObject();

  //clear the pattern string
  clearPattern.SetPatternString("");
  DEBUG("before deserialize:");
  DEBUGEXP(clearPattern.GetPatternString());  
  if (!SerializableHelper::ReadSerializationFromFile(clearFileName+".json", &serObj))
    throw std::runtime_error ("Can't read the clear JSON string from file: "+clearFileName+".json");
  
  if (!clearPattern.Deserialize(serObj)){
    throw std::runtime_error ("Can't deserialize the clear JSON string!");
  };

  DEBUGEXP(clearPattern.GetPatternString());  
  
  DEBUG("done in DeserializeClearPattern");
};

//////////////////////////////////////////////////
void  DeserializeObfuscatedPatternFromFile(const string obfFileName, ObfuscatedLWEConjunctionPattern<DCRTPoly> &obsPattern){

  bool dbg_flag = false;

  DEBUG("in DeserializeObfuscatedPattern");

  Serialized serObj;
  serObj.SetObject();

  //clear the pattern string
  if (!SerializableHelper::ReadSerializationFromFile(obfFileName+".json", &serObj))
    throw std::runtime_error ("Can't read the obfuscated JSON string from the file:"+obfFileName+".json");

  if (!obsPattern.Deserialize(serObj)){
    throw std::runtime_error ("Can't Deserialize the obfuscated JSON string");
  };
  
  DEBUG("done in DeserializeObfuscatedPattern");
};

