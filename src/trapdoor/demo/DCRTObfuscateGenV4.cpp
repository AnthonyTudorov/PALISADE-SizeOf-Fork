/*
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
#include "obfuscation/lweconjunctionobfuscate.cpp"

#include "utils/debug.h"

#include <omp.h> //open MP header TODO DELETE

using namespace lbcrypto;

//forward definitions to be defined later
bool GenerateConjObfs(bool dbg_flag, int  n); 
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
  errorflag = GenerateConjObfs(dbg_flag, n);
  return ((int)errorflag);

}


//////////////////////////////////////////////////////////////////////
bool GenerateConjObfs(bool dbg_flag, int n) {
  //TODO, supply input pattern by file.
  
  //if dbg_flag == true; print debug outputs
  // n = size of vectors to use

  //returns
  //  errorflag = 1 if fail


  TimeVar t1, t_total; //for TIC TOC
  TIC(t_total); //start timer for total time

  usint m = 2*n;
  //54 bits
  //BigInteger modulus("9007199254741169");
  //BigInteger rootOfUnity("7629104920968175");

  usint chunkSize = 8;
  usint base = 1<<20;

  if (n > 1<<10)
    base = 1<<15;

  //Generate the test pattern
  //std::string inputPattern = "1?10?10?1?10?10?1?10?10?1?10??0?";
  //std::string inputPattern = "1?10?10?1?10?10?";
  std::string inputPattern = "1?10?10?";


  ClearLWEConjunctionPattern<DCRTPoly> clearPattern(inputPattern);

  string clearFileName = "cp"+to_string(n);
  SerializeClearPatternToFile(clearPattern, clearFileName);

  //note this is for debug -- will move to evaluate
  ClearLWEConjunctionPattern<DCRTPoly> testClearPattern("");

  DeserializeClearPatternFromFile(clearFileName, testClearPattern);

  DEBUG("clear pattern:           "<<clearPattern.GetPatternString());
  DEBUG("recovered clear pattern: "<<testClearPattern.GetPatternString());  
  
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
  string obfFileName = "op"+to_string(n);
  SerializeObfuscatedPatternToFile(obfuscatedPattern, obfFileName);

  //note this is for debug -- will move to evaluate program once it all works
  ObfuscatedLWEConjunctionPattern<DCRTPoly> testObfuscatedPattern;

  DeserializeObfuscatedPatternFromFile(obfFileName, testObfuscatedPattern);

  if (!CompareObfuscatedPatterns(obfuscatedPattern, testObfuscatedPattern)) {
    std::cout<<"Serialization did not work"<<std::endl;
  }else{
    std::cout<<"Serialization worked correctly"<<std::endl;
  }
  
  DEBUG("Done" );

  //print output timing results
  //note one could use PROFILELOG for these lines
  std::cout << "Timing Summary for n = " << m / 2 << std::endl;
  std::cout << "T: DGG setup time:        " << "\t" << timeDGGSetup << " ms" << std::endl;
  std::cout << "T: Key generation time:        " << "\t" << timeKeyGen << " ms" << std::endl;
  std::cout << "T: Obfuscation execution time: " << "\t" << timeObf << " ms" << std::endl;
  std::cout << "T: Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;


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

  usint n_evals = 3;
  
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

