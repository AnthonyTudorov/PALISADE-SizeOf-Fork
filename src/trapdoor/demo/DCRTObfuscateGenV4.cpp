﻿/*
 * @file 
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology
 * (NJIT) All rights reserved.  Redistribution and use in source and
 * binary forms, with or without modification, are permitted provided
 * that the following conditions are met: 
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#define PROFILE  //define this to enable PROFILELOG and TIC/TOC 
// Note must must be before all headers

#include <iostream>
#include <fstream>
#include "obfuscation/lweconjunctionobfuscate.h"
#include "utils/debug.h"

using namespace lbcrypto;

//forward definitions to be defined later
bool GenerateConjObfs(bool dbg_flag, int n, usint pattern_size, bool eval_flag, usint n_evals = 3);

void  SerializeClearPatternToFile(const ClearLWEConjunctionPattern<DCRTPoly> clearPattern,
				  const string clearFileName);
void  DeserializeClearPatternFromFile(const string clearFileName,
				      ClearLWEConjunctionPattern<DCRTPoly> &clearPattern);
void  SerializeObfuscatedPatternToFile(const ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern,
				       const string obfFileName);
void  DeserializeObfuscatedPatternFromFile(const string obfFileName, ObfuscatedLWEConjunctionPattern<DCRTPoly> &obsPattern);
bool CompareObfuscatedPatterns(ObfuscatedLWEConjunctionPattern<DCRTPoly> &a,
			       ObfuscatedLWEConjunctionPattern<DCRTPoly> &b);

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
  
  
  if (argc < 2) { // called with no arguments
    std::cout << "arg 1 = debugflag 0:1 [0] " << std::endl;
    std::cout << "arg 2 = num bits [10] " << std::endl;    
    //std::cout << "arg 2 = num bit range 0..3 [3] " << std::endl;
    //std::cout << "arg 3 = num evals 1..3 [1] " << std::endl;    
    std::cout << "arg 3 = pattern size [8] 8, 16, 32, 40, 64 " << std::endl;        
  }

  //should become arguments
  usint pattern_size(8);
  //usint pattern_size = 40;
  //usint pattern_size = 64;
  //TODO, supply input pattern by file.
  //TODO, num evals should generate test patterns

  bool eval_flag = true; //if true, also run evaluation to verify correct generation.
  usint n_evals = 3; //number of evaluations to run

  
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
  
  if (argc >= 4 ) { 
    int inarg = atoi(argv[3]);
    if (inarg < 8) {
      pattern_size = 8;
    } else if (inarg >= 64) {
      pattern_size = 64;
    } else {
      pattern_size = inarg;
    }
  }

  if ((pattern_size != 8) &&
      (pattern_size != 16) &&
      (pattern_size != 32) &&
      (pattern_size != 40) &&
      (pattern_size != 64)) {
    std::cout << "bad pattern size: "<< pattern_size << std::endl;
    exit (-1);
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
  	    << n_bits << " bits. Pattern length "<< pattern_size << std::endl;

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
  
  //32 bit test would run n_bits = 10 .. < 10+bit range no max, default 3
// 48 bit test runs 10.. 12  
//64 bit test ran from 1..13
    
  bool errorflag = false;
  unsigned int n = 1<<n_bits;

  errorflag = GenerateConjObfs(dbg_flag, n, pattern_size, eval_flag, n_evals);

  return ((int)errorflag);

}


//////////////////////////////////////////////////////////////////////
bool GenerateConjObfs(bool dbg_flag, int n, usint pattern_size, bool eval_flag, usint n_evals) {
  
  //if dbg_flag == true; print debug outputs
  // n = size of vectors to use (power of 2)
  // pattern_size = size of patterns (8, 32, 40, 64)
  // n_evals number of evals to run 0..3
  
  //returns
  //  errorflag = 1 if fail


  TimeVar t1, t_total; //for TIC TOC
  TIC(t_total); //start timer for total time

  usint m = 2*n;

  usint chunkSize = 8;
  usint base = 1<<20;

  //set inputPattern and adjust base for input pattern size
  std::string inputPattern("");
  switch (pattern_size) {
  case 8:
    inputPattern = "1?10?10?"; //8 bit test
    if (n > 1<<10)   //adjust for 8 bit test (use 32 bit test values)
      base = 1<<15;
    break;

  case 16:
    inputPattern = "1?10?10?1?10?10?"; //16 bit test
    if (n > 1<<10)   //adjust for 16 bit test( use 32 bit test values)
      base = 1<<15;
    break;

  case 32:
    inputPattern = "1?10?10?1?10?10?1?10?10?1?10??0?"; //32 bit test
    if (n > 1<<10)   //adjust for 32 bit test
      base = 1<<15;
    break;
    
  case 40:
    inputPattern = "1?10?10?1?10?10?1?10?10?1?10??0?1?10?10?"; // 40 bit test
    break;
    
  case 64:
    inputPattern = "1?10?10?1?10?10?1?10?10?1?10??0?1?10?10?1?10?10?1?10?10?1?10??0?"; //64 bit test
    
    if (n > 1<<11)   // adjust for 64 bit test
      base = 1<<18;
    break;
  default:
    std::cout<< "bad input pattern length selected (must be 8, 16, 32, 40 or 64). "<<std::endl;
    exit(-1);
  }
  
  
  ClearLWEConjunctionPattern<DCRTPoly> clearPattern(inputPattern);

  string clearFileName = "cp"+to_string(n)+"_"+to_string(pattern_size);
  SerializeClearPatternToFile(clearPattern, clearFileName);

  //note this is for debug -- will move to evaluate
  ClearLWEConjunctionPattern<DCRTPoly> testClearPattern("");

  DeserializeClearPatternFromFile(clearFileName, testClearPattern);

  if (clearPattern.GetPatternString() == testClearPattern.GetPatternString()) {
    std::cout<< "Clear Pattern Serialization succeed"<<std::endl;
  } else {
    std::cout<< "Clear Pattern Serialization FAILED"<<std::endl;
    std::cout<< "    clear pattern:           "<<clearPattern.GetPatternString() <<std::endl;
    std::cout<< "    recovered clear pattern: "<<testClearPattern.GetPatternString()<<std::endl;
  }
  
  
  ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern;
  obfuscatedPattern.SetChunkSize(chunkSize);
  obfuscatedPattern.SetBase(base);
  obfuscatedPattern.SetLength(clearPattern.GetLength());
  obfuscatedPattern.SetRootHermiteFactor(1.006);

  LWEConjunctionObfuscationAlgorithm<DCRTPoly> algorithm;

  //Variables for timing
  double timeDGGSetup(0.0), timeKeyGen(0.0), timeObf(0.0), timeTotal(0.0);

  double stdDev = SIGMA;
  DCRTPoly::DggType dgg(stdDev); // Create the noise generator

  //Finds q using the correctness constraint for the given value of n
  algorithm.ParamsGen(dgg, &obfuscatedPattern, m / 2);

  //this code finds the values of q and n corresponding to the root
  //Hermite factor in obfuscatedPattern

  const shared_ptr<typename DCRTPoly::Params> ilParams = obfuscatedPattern.GetParameters();

  const BigInteger &modulus = ilParams->GetModulus();
  const BigInteger &rootOfUnity = ilParams->GetRootOfUnity();
  m = ilParams->GetCyclotomicOrder();

  PROFILELOG("\nq = " << modulus);
  PROFILELOG("rootOfUnity = " << rootOfUnity);
  PROFILELOG("n = " << m / 2);
  PROFILELOG(printf("delta=%lf", obfuscatedPattern.GetRootHermiteFactor()));
  PROFILELOG("\nbase = " << base);

  typename DCRTPoly::DugType dug;
  typename DCRTPoly::TugType tug;

  PROFILELOG("\nCryptosystem initialization: Performing precomputations...");

  //This code is run only when performing execution time measurements

  //Precomputations for FTT
  DiscreteFourierTransform::PreComputeTable(m);

  ////////////////////////////////////////////////////////////
  //Generate and save the obfuscated pattern
  ////////////////////////////////////////////////////////////
  bool errorflag = false;

  PROFILELOG("Key generation started");
  TIC(t1);
  algorithm.KeyGen(dgg, &obfuscatedPattern);
  timeKeyGen = TOC(t1);
  PROFILELOG("Key generation time: " << "\t" << timeKeyGen << " ms");

  BinaryUniformGenerator dbg = BinaryUniformGenerator();

  DEBUG("Obfuscation Generation started");
  TIC(t1);
  algorithm.Obfuscate(clearPattern, dgg, tug, &obfuscatedPattern);
  timeObf = TOC(t1);
  PROFILELOG("Obfuscation time: " << "\t" << timeObf << " ms");
  //get the total program run time.
  timeTotal = TOC(t_total);


  DEBUG("Serializing Obfuscation" );
  string obfFileName = "op"+to_string(n)+"_"+to_string(pattern_size);
  SerializeObfuscatedPatternToFile(obfuscatedPattern, obfFileName);


  ObfuscatedLWEConjunctionPattern<DCRTPoly> testObfuscatedPattern;

  DeserializeObfuscatedPatternFromFile(obfFileName, testObfuscatedPattern);

  if (!CompareObfuscatedPatterns(obfuscatedPattern, testObfuscatedPattern)) {
    std::cout<<"Serialization did verify"<<std::endl;
  }else{
    std::cout<<"Serialization verified"<<std::endl;
  }
  
  DEBUG("Done" );

  //print output timing results
  //note one could use PROFILELOG for these lines
  std::cout << "Timing Summary for n = " << m / 2 << std::endl;
  std::cout << "T: DGG setup time:        " << "\t" << timeDGGSetup << " ms" << std::endl;
  std::cout << "T: Key generation time:        " << "\t" << timeKeyGen << " ms" << std::endl;
  std::cout << "T: Obfuscation execution time: " << "\t" << timeObf << " ms" << std::endl;
  std::cout << "T: Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;



  if (eval_flag) {
      
    ////////////////////////////////////////////////////////////
    //Test the cleartext pattern
    ////////////////////////////////////////////////////////////

    DEBUG(" \nCleartext pattern: ");
    DEBUG(clearPattern.GetPatternString());

    DEBUG(" \nCleartext pattern length: ");
    DEBUG(clearPattern.GetLength());

    std::string inputStr1("");
    std::string inputStr2("");
    std::string inputStr3("");
    switch (pattern_size) {
    case 8:  //8 bit test
      inputStr1 = "11100100";
      inputStr2 = "11001101";
      inputStr3 = "10101101";
      break;

    case 16:
      inputStr1 = "1110010011100100";
      inputStr2 = "1100110111001101";
      inputStr3 = "1010110110101101";
      break;

    case 32:  //32 bit test
      inputStr1 = "11100100111001001110010011100100";
      inputStr2 = "11001101110011011100110111001111";
      inputStr3 = "10101101101011011010110110101101";
      break;
    
    case 40:  //40 bit test
      inputStr1 = "1110010011100100111001001110010011100100"; 
      inputStr2 = "1100110111001101110011011100111111001101"; 
      inputStr3 = "1010110110101101101011011010110110101101"; 
      break;
    
    case 64:  // 64 bit test
      inputStr1 = "1110010011100100111001001110010011100100111001001110010011100100";
      inputStr2 = "1100110111001101110011011100111111001101110011011100110111001111";
      inputStr3 = "1010110110101101101011011010110110101101101011011010110110101101";
      break;

    default:
      std::cout<< "bad input pattern length selected (must be 32, 40 or 64). "<<std::endl;
      exit(-1);
    }
      
    //std::string inputStr1 = "11100100"; //8 bit test
    //std::string inputStr2 = "11001101"; //8 bit test
    //std::string inputStr3 = "10101101"; //8 bit test

    bool out1 = algorithm.Evaluate(clearPattern, inputStr1);
    DEBUG(" \nCleartext pattern evaluation of: " << inputStr1 << " is " << out1);

    bool out2 = algorithm.Evaluate(clearPattern, inputStr2);
    DEBUG(" \nCleartext pattern evaluation of: " << inputStr2 << " is " << out2);
  
    bool out3 = algorithm.Evaluate(clearPattern, inputStr3);
    DEBUG(" \nCleartext pattern evaluation of: " << inputStr3 << " is " << out3);
	
    ////////////////////////////////////////////////////////////
    //Generate and test the obfuscated pattern
    ////////////////////////////////////////////////////////////
    double timeEval1(0.0),  timeEval2(0.0),  timeEval3(0.0);

    //todo make this a loop
    bool result1 = false;
    bool result2 = false;
    bool result3 = false;
    std::cout << " \nCleartext pattern: " << std::endl;
    std::cout << clearPattern.GetPatternString() << std::endl;

    PROFILELOG("Evaluation started");
    DEBUG("====== just before eval ");  
    DEBUGEXP(*(obfuscatedPattern.GetParameters()));

    DEBUG("====== ");  
    TIC(t1);
    result1 = algorithm.Evaluate(obfuscatedPattern, inputStr1);
    timeEval1 = TOC(t1);
    DEBUG(" \nCleartext pattern evaluation of: " << inputStr1 << " is " << result1 << ".");
    PROFILELOG("Evaluation 1 execution time: " << "\t" << timeEval1 << " ms");

    errorflag = false;
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
  }
  
  DiscreteFourierTransform::Reset();
  
  return (errorflag);
}

//////////////////////////////////////////////////
void  SerializeClearPatternToFile(const ClearLWEConjunctionPattern<DCRTPoly> clearPattern, const string clearFileName){

  bool dbg_flag = false;

  DEBUG("in SerializeClearPattern");

  Serialized serObj;
  serObj.SetObject();

  clearPattern.Serialize(&serObj);

  if (!SerializableHelper::WriteSerializationToFile(serObj, clearFileName+".json"))
    throw std::runtime_error ("Can't write the clear pattern to file: " +clearFileName+".json");

  if (!SerializableHelper::WriteSerializationToPrettyFile(serObj, clearFileName+"pretty.json"))
    throw std::runtime_error ("Can't write the clear pattern to the pretty file:"+clearFileName+"pretty.json");

  DEBUG("done in SerializeClearPattern");
};

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

////////////////////////////////////////////////////////
void  SerializeObfuscatedPatternToFile(const ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern, const string obfFileName){
  bool dbg_flag = false;

  DEBUG("in SerializeObfuscatedPattern");
  DEBUGEXP(*obfuscatedPattern.GetParameters());

  Serialized serObj;
  serObj.SetObject();
  
  obfuscatedPattern.Serialize(&serObj);
  
  if (!SerializableHelper::WriteSerializationToFile(serObj, obfFileName+".json"))
    throw std::runtime_error ("Can't write the obfuscated JSON string to the file: "+obfFileName+".json" );

  if (!SerializableHelper::WriteSerializationToPrettyFile(serObj, obfFileName+"pretty.json"))
    throw std::runtime_error ("Can't write the obfuscated JSON string to the pretty file: "+obfFileName+"pretty.json" );
  
  DEBUG("done in SerializeObfuscatedPattern");

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


////////////////////////////////////////////////
bool CompareObfuscatedPatterns(ObfuscatedLWEConjunctionPattern<DCRTPoly> &a, ObfuscatedLWEConjunctionPattern<DCRTPoly> &b){
  bool dbg_flag = true;
  DEBUG("in CompareObfuscatedPattern");
  
  return(a.Compare(b));

};

