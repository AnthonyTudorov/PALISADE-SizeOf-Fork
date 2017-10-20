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
void  SerializeClearPattern(ClearLWEConjunctionPattern<DCRTPoly> clearPattern);
void  DeserializeClearPattern(ClearLWEConjunctionPattern<DCRTPoly> &clearPattern);
void  SerializeObfuscatedPattern(ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern);
void  DeserializeObfuscatedPattern(ObfuscatedLWEConjunctionPattern<DCRTPoly> &obsPattern);

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

  SerializeClearPattern(clearPattern);
    
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
  DiscreteFourierTransform::GetInstance().PreComputeTable(m);

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

  DEBUG("Serializing Obfuscation" );

  SerializeObfuscatedPattern(obfuscatedPattern);

  DEBUG("Done" );
  //get the total program run time.
  timeTotal = TOC(t_total);

  //print output timing results
  //note one could use PROFILELOG for these lines
  std::cout << "Timing Summary for n = " << m / 2 << std::endl;
  std::cout << "T: DGG setup time:        " << "\t" << timeDGGSetup << " ms" << std::endl;
  std::cout << "T: Key generation time:        " << "\t" << timeKeyGen << " ms" << std::endl;
  std::cout << "T: Obfuscation execution time: " << "\t" << timeObf << " ms" << std::endl;
  std::cout << "T: Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

  DiscreteFourierTransform::GetInstance().Destroy();
  return (errorflag);
}
//////////////////////////////////////////////////////////////
void  DeserializeClearPattern(ClearLWEConjunctionPattern<DCRTPoly> &clearPattern){

  bool dbg_flag = true;

  DEBUG("in DeserializeClearPattern");

  Serialized serObj;
  serObj.SetObject();

  //clear the pattern string
  clearPattern.SetPatternString("");
  DEBUG("before deserialize:");
  DEBUGEXP(clearPattern.GetPatternString());  
  if (!SerializableHelper::ReadSerializationFromFile("cp.json", &serObj))
    throw std::runtime_error ("Can't read the JSON string from the file!");

  
  if (!clearPattern.Deserialize(serObj)){
    throw std::runtime_error ("Can't deserialize the JSON string!");
  };

  DEBUGEXP(clearPattern.GetPatternString());  
  
  DEBUG("done in DeserializeClearPattern");
};

void  SerializeClearPattern(ClearLWEConjunctionPattern<DCRTPoly> clearPattern){

  bool dbg_flag = true;

  DEBUG("in SerializeClearPattern");

  Serialized serObj;
  serObj.SetObject();


  clearPattern.Serialize(&serObj);

#if 0  
  std::ofstream of ("cp.json");
  if (!SerializableHelper::SerializationToStream(serObj, of))
    throw std::runtime_error ("Can't write the clear pattern to the file!");
  of.close();
#else
  if (!SerializableHelper::WriteSerializationToFile(serObj, "cp.json"))
    throw std::runtime_error ("Can't write the clear pattern to the file!");
#endif

  DeserializeClearPattern(clearPattern);
  
  DEBUG("done in SerializeClearPattern");
};

void  DeserializeObfuscatedPattern(ObfuscatedLWEConjunctionPattern<DCRTPoly> &obsPattern){

  bool dbg_flag = true;

  DEBUG("in DeserializeObfuscatedPattern");

  Serialized serObj;
  serObj.SetObject();

  //clear the pattern string

  DEBUG("before deserialize:");
  DEBUGEXP(obsPattern);  

  if (!SerializableHelper::ReadSerializationFromFile("op.json", &serObj))
    throw std::runtime_error ("Can't read the JSON string from the file!");

  
  if (!obsPattern.Deserialize(serObj)){
    throw std::runtime_error ("Can't Deserialize the JSON string");
  };

  DEBUGEXP(obsPattern);  
  
  DEBUG("done in DeserializeObfuscatedPattern");
};



void  SerializeObfuscatedPattern(ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern){
  bool dbg_flag = true;

  DEBUG("in SerializeObfuscatedPattern");
  
  Serialized serObj;
  serObj.SetObject();
  
  
  DEBUG("obfuscated pattern");
  
  std::cout<<obfuscatedPattern<< std::endl;
  
  obfuscatedPattern.Serialize(&serObj);
  
  if (!SerializableHelper::WriteSerializationToFile(serObj, "op.json"))
    throw std::runtime_error ("Can't write the JSON string to the file!");
  
  DeserializeObfuscatedPattern(obfuscatedPattern);
  
  DEBUG("done in SerializeObfuscatedPattern");
  


};

