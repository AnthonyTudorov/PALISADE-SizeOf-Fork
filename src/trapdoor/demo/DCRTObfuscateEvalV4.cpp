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
#include "utils/debug.h"

using namespace lbcrypto;

bool EvaluateConjObfs(bool dbg_flag, int  n, usint pattern_size, usint num_evals); //defined later

void  DeserializeClearPatternFromFile(const string clearFileName,
				      ClearLWEConjunctionPattern<DCRTPoly> &clearPattern);
void  DeserializeObfuscatedPatternFromFile(const string obfFileName, ObfuscatedLWEConjunctionPattern<DCRTPoly> &obsPattern, bool checkflag = false);
void  SerializeObfuscatedPatternToFile(const ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern,
				       const string obfFileName);
//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
  
  
  if (argc < 2) { // called with no arguments
    std::cout << "arg 1 = debugflag 0:1 [0] " << std::endl;
    std::cout << "arg 2 = num bits [10] " << std::endl;
    std::cout << "arg 3 = pattern size [8] 8, 16, 32, 40, 64 " << std::endl;        

    //std::cout << "arg 2 = num bit range 0..3 [3] " << std::endl;
    //std::cout << "arg 3 = num evals 1..3 [1] " << std::endl;    
  }
  //should become arguments
  usint pattern_size (8);
  //usint pattern_size = 40;
  //usint pattern_size = 64;
  //TODO, num evals should generate test patterns

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
    
  bool errorflag = false;
  unsigned int n = 1<<n_bits;
  errorflag = EvaluateConjObfs(dbg_flag, n, pattern_size, n_evals);
  return ((int)errorflag);

}


//////////////////////////////////////////////////////////////////////
bool EvaluateConjObfs(bool dbg_flag, int n, usint pattern_size, usint n_evals) {

  //if dbg_flag == true; print debug outputs
  // n = size of vectors to use

  //returns
  //  errorflag = 1 if fail


  TimeVar t1, t_total; //for TIC TOC
  float timeRead(0.0);

  usint m = 2*n;

  //Read the test pattern from the file
  ClearLWEConjunctionPattern<DCRTPoly> clearPattern("");
  string clearFileName = "cp"+to_string(n)+"_"+to_string(pattern_size);

  DEBUG("reading clearPattern from file: "<<clearFileName<<".json");
  TIC(t1);
  DeserializeClearPatternFromFile(clearFileName, clearPattern);
  timeRead = TOC(t1);
  PROFILELOG("Read time: " << "\t" << timeRead << " ms");

  string obfFileName = "op"+to_string(n)+"_"+to_string(pattern_size);
  //note this is for debug -- will move to evaluate program once it all works
  ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern;

  std::cout<<"Deserializing Obfuscated Pattern from file "+obfFileName+".json"<<std::endl;
  TIC(t1);
  DeserializeObfuscatedPatternFromFile(obfFileName, obfuscatedPattern);
  timeRead = TOC(t1);
  PROFILELOG("Done, Read time: " << "\t" << timeRead << " ms");


  TIC(t_total); //start timer for total time

  LWEConjunctionObfuscationAlgorithm<DCRTPoly> algorithm;
    
  //Variables for timing
  //todo make eval an array
  double timeEval1(0.0), timeEval2(0.0), timeEval3(0.0), timeTotal(0.0);


  const shared_ptr<typename DCRTPoly::Params> ilParams = obfuscatedPattern.GetParameters();

  m = ilParams->GetCyclotomicOrder();
  
  double stdDev = SIGMA;
  DCRTPoly::DggType dgg(stdDev);			// Create the noise generator

  //Precomputations for FTT
  DiscreteFourierTransform::PreComputeTable(m);

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
  
  case 8:
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
    std::cout<< "bad input pattern length selected (must be 8, 16, 32, 40 or 64). "<<std::endl;
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

  //todo make this a loop
  bool result1 = false;
  bool result2 = false;
  bool result3 = false;

  PROFILELOG("Evaluation started");
  //DEBUG("====== just before eval ");  
  //DEBUGEXP(*(obfuscatedPattern.GetParameters()));

  //DEBUG("====== ");  
  TIC(t1);
  result1 = algorithm.Evaluate(obfuscatedPattern, inputStr1);
  timeEval1 = TOC(t1);

  DEBUG(" \nCleartext pattern evaluation of: " << inputStr1 << " is " << result1 << ".");
  PROFILELOG("Evaluation 1 execution time: " << "\t" << timeEval1 << " ms");

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
void  DeserializeObfuscatedPatternFromFile(const string obfFileName, ObfuscatedLWEConjunctionPattern<DCRTPoly> &obsPattern, bool checkflag){

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

  if (checkflag) {
    SerializeObfuscatedPatternToFile(obsPattern, obfFileName+"check");
  }

  DEBUG("done in DeserializeObfuscatedPattern");

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
