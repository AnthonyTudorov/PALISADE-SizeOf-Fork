/**
 *  @file
 *  PRE SCHEME PROJECT, Crypto Lab, NJIT 
 *  @version v01.0
 *  @author TPOC: Dr. Kurt Rohloff, <rohloff@njit.edu> 
 *  Programmers: 
 *  Dr. Yuriy Polyakov, <polyakov@njit.edu>
 *  Gyana Sahu, <grs22@njit.edu> 
 *  Dr. David Bruce Cousins, <dcousins@bbn.com>
 *
 *  @section LICENSE
 *
 *  Copyright (c) 2015, New Jersey Institute of Technology (NJIT) All
 *  rights reserved.  Redistribution and use in source and binary forms,
 *  with or without modification, are permitted provided that the
 *  following conditions are met: 1. Redistributions of source code must
 *  retain the above copyright notice, this list of conditions and the
 *  following disclaimer.  2. Redistributions in binary form must
 *  reproduce the above copyright notice, this list of conditions and the
 *  following disclaimer in the documentation and/or other materials
 *  provided with the distribution.  THIS SOFTWARE IS PROVIDED BY THE
 *  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL uTHE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 *  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 *  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  @section DESCRIPTION
 *
 *  This file contains google test code that exercises the big int
 *  vector library of the PALISADE lattice encryption library.
 *
 **/

//todo reduce the number of required includes
#include "../include/gtest/gtest.h"
#include <iostream>
#include <fstream>

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/math/nbtheory.h"

#include "../../src/lib/lattice/elemparams.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/lattice/ilelement.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/crypto/lwecrypt.h"
#include "../../src/lib/crypto/lwepre.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"
#include "../../src/lib/utils/utilities.h"

using namespace std;
using namespace lbcrypto;

/*
  int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  }
*/

 //helper function to compare two bintvecs and print differing indicies
 void vec_diff(ubintvec &a, ubintvec &b) {
   for (usint i= 0; i < a.size(); ++i){  //todo change to size()
     if (a[i] != b[i]) {  //todo: add [] indexing to class
       cout << "i: "<< i << endl;
       cout << "first vector " <<endl;
       cout <<a[i];
       cout << endl;
       cout << "state " << a[i].GetState() << endl;;
       cout << "msb: " << a[i].GetMSB() << endl;;
       cout << "second vector " <<endl;
       cout << b[i];
       cout << endl;
       cout << "state " << b[i].GetState() << endl;;
       cout << "msb: " << b[i].GetMSB() << endl;;
       cout << endl;
     }
   }
 }

class UnitTestubintvec : public ::testing::Test {
protected:
  virtual void SetUp() {
    // Code here will be called before each test
    // (right before the constructor).

  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/* list of tests left to run

   //METHODS
   //todo write Div and /= vector scalar and vector vector
   
   Exp(const bint_el_t &b)

   GetDigitAtIndexForBase(usint index, usint base) const;
   
   //JSON FACILITY
   Serialize()
   Deserialize()
   

/************************************************/
/*	TESTING BASIC METHODS OF ubintvec CLASS        */
/************************************************/
TEST(UTubintvec,ctor_access_eq_neq){

  ubintvec m(5); // calling constructor to create a vector of length 5
                 //note all values are zero.
  ubintvec n(5);

  int i;
  usint j;

  EXPECT_EQ(5,m.size())<< "Failure in size()";
  EXPECT_EQ(5,n.size())<< "Failure in size()";

  //setting value of the value at different index locations

  m.SetValAtIndex(0,"9868");  //SetValAtIndex(str)
  m.SetValAtIndex(1,"5879");
  m.SetValAtIndex(2,"4554");
  m.SetValAtIndex(3,"2343");
  m.SetValAtIndex(4,"4624");

  EXPECT_EQ(9868U,m.GetValAtIndex(0).ConvertToUsint())<< "Failure in SetValAtIndex(str)";
  EXPECT_EQ(5879U,m.GetValAtIndex(1).ConvertToUsint())<< "Failure in SetValAtIndex(str)";
  EXPECT_EQ(4554U,m.GetValAtIndex(2).ConvertToUsint())<< "Failure in SetValAtIndex(str)";
  EXPECT_EQ(2343U,m.GetValAtIndex(3).ConvertToUsint())<< "Failure in SetValAtIndex(str)";
  EXPECT_EQ(4624U,m.GetValAtIndex(4).ConvertToUsint())<< "Failure in SetValAtIndex(str)";

  EXPECT_EQ(ubint(9868U),m.GetValAtIndex(0))<< "Failure in SetValAtIndex()";
  EXPECT_EQ(ubint(5879U),m.GetValAtIndex(1))<< "Failure in SetValAtIndex()";
  EXPECT_EQ(ubint(4554U),m.GetValAtIndex(2))<< "Failure in SetValAtIndex()";
  EXPECT_EQ(ubint(2343U),m.GetValAtIndex(3))<< "Failure in SetValAtIndex()";
  EXPECT_EQ(ubint(4624U),m.GetValAtIndex(4))<< "Failure in SetValAtIndex()";

  //setting value of the value at different index locations

  n[0]="4";
  n[1]=9;   //int (implied)
  n[2]=ubint("66"); //ubint
  n[3] = 33L;  //long
  n[4] = 7UL;  //unsigned long


  EXPECT_EQ(ubint(4),n[0])<< "Failure in []";
  EXPECT_EQ(ubint(9),n[1])<< "Failure in []";
  EXPECT_EQ(ubint(66),n[2])<< "Failure in []";
  EXPECT_EQ(ubint(33),n[3])<< "Failure in []";
  EXPECT_EQ(ubint(7),n[4])<< "Failure in []";

  n.SetValAtIndex(0,ubint("4")); //test SetValAtIndex(ubint)
  n.SetValAtIndex(1,ubint("9"));
  n.SetValAtIndex(2,ubint("66"));
  n.SetValAtIndex(3,ubint("33"));
  n.SetValAtIndex(4,ubint("7"));


  EXPECT_EQ(ubint(4),n[0])<< "Failure in SetValAtIndex(ubint)";
  EXPECT_EQ(ubint(9),n[1])<< "Failure in SetValAtIndex(ubint)";
  EXPECT_EQ(ubint(66),n[2])<< "Failure in SetValAtIndex(ubint)";
  EXPECT_EQ(ubint(33),n[3])<< "Failure in SetValAtIndex(ubint)";
  EXPECT_EQ(ubint(7),n[4])<< "Failure in SetValAtIndex(ubint)";

  m+=n;

  usint expectedResult[5] = {9872,5888,4620,2376,4631};

  for (i=0,j=0;j<5;i++,j++) {
    EXPECT_EQ (expectedResult[i], (m.GetValAtIndex(j)).ConvertToUsint())
      << "Failure testing method_plus_equals";
  }
  //test initializer list
  ubintvec expectedvecstr(5);
  expectedvecstr = {"9872","5888","4620","2376","4631"}; 
  EXPECT_EQ (expectedvecstr, m)<< "Failure string initializer list";
  
  ubintvec expectedvecint(5);
  expectedvecint = {ubint(9872U),ubint(5888U),ubint(4620U),ubint(2376U),ubint(4631U)};
  EXPECT_EQ (expectedvecint, m)<< "Failure ubint initializer list";

  expectedvecint = {9872U,5888u,4620u,2376u,4631u};
  EXPECT_EQ (expectedvecint, m)<< "Failure usint initializer list";

  expectedvecint = {9872,5888,4620,2376,4631}; //fails
  EXPECT_EQ (expectedvecint, m)<< "Failure int initializer list";

  //test Single
  ubintvec s = ubintvec::Single(ubint("3"));
		      
  EXPECT_EQ(1, s.size()) <<"Failure Single.size()";
  EXPECT_EQ(ubint(3), s[0]) <<"Failure Single() value";

  // test assignment of single ubit (puts it in the 0 the position)
  ubintvec eqtest(10);
  EXPECT_EQ ( 10, eqtest.size()) << "Failure create ubintvec of 10 zeros";

  for (i = 0; i< eqtest.size(); i++) {
    EXPECT_EQ ( ubint(0U), eqtest[i]) << "Failure create ubintvec of zeros";
  }

  // test assignment of single ubint
  eqtest = ubint(1);
  EXPECT_EQ (ubint(1),  eqtest[0]) << "Failure assign single ubint 0 index";
  for (i = 1; i< eqtest.size(); i++) {
    EXPECT_EQ ( ubint(0U), eqtest[i]) << "Failure assign single ubint nonzero index";
  }

  // test assignment of single usint
  eqtest = 5U;
  EXPECT_EQ (ubint(5U),  eqtest[0]) << "Failure assign single ubint 0 index";
  for (i = 1; i< eqtest.size(); i++) {
    EXPECT_EQ ( ubint(0U), eqtest[i]) << "Failure assign single ubint nonzero index";
  }

  //test == and !=
  m = n;
  bool test1 = m==n;
  bool test2 = m!=n;
  EXPECT_TRUE(test1)<<"Failure ==";
  EXPECT_FALSE(test2)<<"Failure !=";

  m = n+n;
  test1 = m==n;
  test2 = m!=n;
  EXPECT_FALSE(test1)<<"Failure ==";
  EXPECT_TRUE(test2)<<"Failure !=";

  for (auto i = 0; i < m.size(); i++) {
    m[i] = n[i]; //test both lhs and rhs []
  }
  test1 = m==n;
  EXPECT_TRUE(test1)<<"Failure [] lhs rhs";


}
/************************************************/
/*	TESTING BASIC operators OF ubintvec CLASS        */
/************************************************/

/************************************************/
/*	TESTING SCALAR MATH OF ubintvec CLASS        */
/************************************************/


//---------------------TESTING INTEGER OPERATIONS ON VECTOR---------------------------------//

/*
  GetValAtIndex() operates on BigBinary Vector, retrieves the value at the given index of a vector
  The functions returns BigBinaryInterger, which is passed to ConvertToUsint() to convert to integer
  One dimensional integer array expectedResult is created
  Indivdual expected result for each index of the vector is store in array
  EXPECT_EQ is given the above integer from GetValAtIndex, and the value of the expectedResult at the corresponding index
*/ 




/*--------------TESTING METHOD MODULUS FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod" operates on BigBinary Vector m, BigBinary Integer q
  	Returns:  m mod q, and the result is stored in BigBinary Vector calculatedResult.
*/

TEST(UTubintvec,mod){
  //note this is the 'old code'
  ubintvec m(10);				// calling constructor to create a vector of length 10

  int i;
  usint j;
	
  //setting value of the value at different index locations
  m.SetValAtIndex(0,"987968");
  m.SetValAtIndex(1,"587679");
  m.SetValAtIndex(2,"456454");
  m.SetValAtIndex(3,"234343");
  m.SetValAtIndex(4,"769789");
  m.SetValAtIndex(5,"465654");
  m.SetValAtIndex(6,"79");
  m.SetValAtIndex(7,"346346");
  m.SetValAtIndex(8,"325328");
  m.SetValAtIndex(9,"7698798");	

  ubint q("233");		//calling costructor of ubint Class to create object for modulus
  ubintvec calculatedResult = m.Mod(q);
  usint expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};	// the expected values are stored as one dimensional integer array

  for (i=0,j=0;i<10;i++,j++)
    {
      EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToUsint());
    }
}


TEST(UTubintvec,basic_vector_scalar_math_1_limb){
  //basic vector math with 1 limb entries
  // a1:
  std::vector<std::string>  a1sv =
    { "127753", "077706",
      "017133", "022582",
      "112132", "027625",
      "126773", "008924",
      "125972", "002551",
      "113837", "112045",
      "100953", "077352",
      "132013", "057029", };
  
  ubintvec a1(a1sv);
  ubintvec a1op1(a1.size());
  ubintvec a1op1test(a1.size());
  
  ubint myone(ubint::ONE);

  // test all scalar operations with ONE as the operator term

  // add
  for (usint i = 0; i < a1.size();i ++){ //build test vector
    a1op1[i] = a1[i]+myone;
  }

  a1op1test = a1.Add(myone);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Add()"; 

  a1op1test = a1 + myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar +";   

  a1op1test = a1;
  a1op1test += myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar +=";   

  // sub
  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]-myone;
  }
  a1op1test = a1.Sub(myone);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Sub()"; 

  a1op1test = a1 - myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar -";   

  a1op1test = a1;
  a1op1test -= myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar -=";   

  // multiply
  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]*myone;
  }
  a1op1test = a1.Mul(myone);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Mul()"; 

  a1op1test = a1 * myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar *";   

  a1op1test = a1;
  a1op1test *= myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar *=";   

}



TEST(UTubintvec,basic_vector_vector_math_1_limb){
  //basic vector math with 1 limb entries
  // a1:
  std::vector<std::string>  a1sv =
    { "127753", "077706",
      "017133", "022582",
      "112132", "027625",
      "126773", "008924",
      "125972", "002551",
      "113837", "112045",
      "100953", "077352",
      "132013", "057029", };

  ubintvec a1(a1sv);

  // b1:
  std::vector<std::string>  b1sv = 
    {"066773", "069572",
     "142134", "141115",
     "123182", "155822",
     "128147", "094818",
     "135782", "030844",
     "088634", "099407",
     "053647", "111689",
     "028502", "026401", };

  ubintvec b1(b1sv);

  // add1:
  std::vector<std::string>  add1sv = 
    {"194526", "147278",
     "159267", "163697",
     "235314", "183447",
     "254920", "103742",
     "261754", "033395",
     "202471", "211452",
     "154600", "189041",
     "160515", "083430", };

  ubintvec add1(add1sv);
  // sub1:
#if 0 //set to 1 if we allow b>a in subtraction
  std::vector<std::string>  sub1sv = 
    {"060980", "008134",
     "18446744073709426615", "18446744073709433083",
     "18446744073709540566", "18446744073709423419",
     "18446744073709550242", "18446744073709465722",
     "18446744073709541806", "18446744073709523323",
     "025203", "012638",
     "047306", "18446744073709517279",
     "103511", "030628", };

#else
  std::vector<std::string> sub1sv = 

    {"060980", "008134",
     "000000", "000000",
     "000000", "000000",
     "000000", "000000",
     "000000", "000000",
     "025203", "012638",
     "047306", "000000",
     "103511", "030628", };
#endif
  ubintvec sub1(sub1sv);

  // mul1:
  std::vector<std::string>  mul1sv = 
    {"08530451069",
     "05406161832",
     "02435181822",
     "03186658930",
     "13812644024",
     "04304582750",
     "16245579631",
     "00846155832",
     "17104730104",
     "00078683044",
     "10089828658",
     "11138057315",
     "05415825591",
     "08639367528",
     "03762634526",
     "01505622629", };
  ubintvec mul1(mul1sv);

  ubintvec c1;
  ubintvec d1;
  mubintvec mc1;
  // test math for case 1
  c1 = a1.Add(b1);
  EXPECT_EQ (c1, add1) << "Failure 1 limb vector vector Add()";
  c1 = a1 + b1;
  EXPECT_EQ (c1, add1) << "Failure 1 limb vector vector +";

  d1 = a1;
  d1+=b1;
  EXPECT_EQ (d1, add1) << "Failure 1 limb vector vector +=";


  c1 = a1.Sub(b1);
  EXPECT_EQ (c1, sub1) << "Failure 1 limb vector vector Sub()";
  c1 = a1 - b1;
  EXPECT_EQ (c1, sub1) << "Failure 1 limb vector vector -";
  d1 = a1;
  d1 -= b1;
  EXPECT_EQ (d1, sub1) << "Failure 1 limb vector vector -=";

  c1 = a1.Mul(b1);
  EXPECT_EQ (c1, mul1) << "Failure 1 limb vector vector Mul()";
  c1 = a1 * b1;
  EXPECT_EQ (c1, mul1) << "Failure 1 limb vector vector *";
  d1 = a1;
  d1 *= b1;
  EXPECT_EQ (d1, mul1) << "Failure 1 limb vector vector *=";

}


TEST(UTubintvec,basic_vector_scalar_mod_math_1_limb){
  //basic vector scalar mod math
  //todo this is very simple, should probably add sub mul by bigger numbers.

  // q1 modulus 1:
  ubint q1("163841");

  // a1:
  std::vector<std::string>  a1sv =
    { "127753", "077706",
      "017133", "022582",
      "112132", "027625",
      "126773", "008924",
      "125972", "002551",
      "113837", "112045",
      "100953", "077352",
      "132013", "057029", };
  
  ubintvec a1(a1sv);
  ubintvec a1op1(a1.size());
  ubintvec a1op1test(a1.size());
  
  ubint myone(ubint::ONE);
  
  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]+myone;
    a1op1[i] %= q1;
  }
  a1op1test = a1.ModAdd(myone, q1);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Add()"; 

  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]-myone;
    a1op1[i] %= q1;
  }
  a1op1test = a1.ModSub(myone, q1);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Sub()"; 

  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]*myone;
    a1op1[i] %= q1;
  }
  a1op1test = a1.ModMul(myone, q1);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Mul()"; 

}


TEST(UTubintvec,basic_vector_vector_mod_math_1_limb){

  // q1 modulus 1:
  ubint q1("163841");

  // a1:
  std::vector<std::string>  a1sv =
    { "127753", "077706",
      "017133", "022582",
      "112132", "027625",
      "126773", "008924",
      "125972", "002551",
      "113837", "112045",
      "100953", "077352",
      "132013", "057029", };

  ubintvec a1(a1sv);

  // b1:
  std::vector<std::string>  b1sv = 
    {"066773", "069572",
     "142134", "141115",
     "123182", "155822",
     "128147", "094818",
     "135782", "030844",
     "088634", "099407",
     "053647", "111689",
     "028502", "026401", };

  ubintvec b1(b1sv);
 
  // modadd1:
  std::vector<std::string>  modadd1sv = 
    {"030685", "147278",
     "159267", "163697",
     "071473", "019606",
     "091079", "103742",
     "097913", "033395",
     "038630", "047611",
     "154600", "025200",
     "160515", "083430", };
  ubintvec modadd1(modadd1sv);

  // modsub1:
  std::vector<std::string>  modsub1sv = 
    {"060980", "008134",
     "038840", "045308",
     "152791", "035644",
     "162467", "077947",
     "154031", "135548",
     "025203", "012638",
     "047306", "129504",
     "103511", "030628", };
  ubintvec modsub1(modsub1sv);

  // modmul1:
  std::vector<std::string>  modmul1sv = 
    {"069404", "064196",
     "013039", "115321",
     "028519", "151998",
     "089117", "080908",
     "057386", "039364",
     "008355", "146135",
     "061336", "031598",
     "025961", "087680", };
  ubintvec modmul1(modmul1sv);

  ubintvec c1;
 //now Mod operations
  c1 = a1.ModAdd(b1,q1);
  EXPECT_EQ (c1, modadd1) << "Failure 1 limb vector vector ModAdd()";    

  c1 = a1.ModSub(b1,q1);
  EXPECT_EQ (c1, modsub1) << "Failure 1 limb vector vector ModSub()";   

  c1 = a1.ModMul(b1,q1);
  EXPECT_EQ (c1, modmul1) << "Failure 1 limb vector vector ModMul()";   

  c1 = a1.Add(b1);
  c1  %= q1;
  EXPECT_EQ (c1, modadd1) << "Failure 1 limb vector scalar %";   

}

TEST(UTubintvec,basic_vector_scalar_math_2_limb){
  //basic vector math with 2 limb entries
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };

  
  ubintvec a2(a2sv);
  ubintvec a2op1(a2.size());
  ubintvec a2op1test(a2.size());
  
  ubint myone(ubint::ONE);
  
  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]+myone;
  }
  a2op1test = a2.Add(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Add()"; 

  a2op1test = a2 + myone;
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar +";   

  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]-myone;
  }
  a2op1test = a2.Sub(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Sub()"; 

  a2op1test = a2 - myone;
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar -";   

  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]*myone;
  }
  a2op1test = a2.Mul(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Mul()"; 

  a2op1test = a2 * myone;
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar *";   

}

TEST(UTubintvec,basic_vector_vector_math_2_limb){

  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  ubintvec a2(a2sv);

  // b2:
  std::vector<std::string>  b2sv = 
    {"0698898215124963", "0039832572186149",
     "1835473200214782", "1041547470449968",
     "1076152419903743", "0433588874877196",
     "2336100673132075", "2990190360138614",
     "0754647536064726", "0702097990733190",
     "2102063768035483", "0119786389165930",
     "3976652902630043", "3238750424196678",
     "2978742255253796", "2124827461185795", };

  ubintvec b2(b2sv);

  // add2:
  std::vector<std::string>  add2sv = 
    {"0884123387923218", "0138712237895312",
     "5332883231566040", "5053979403959223",
     "2619173177932324", "0568683443309337",
     "6313055010273814", "7020538881695734",
     "0930588339595881", "1137334268426157",
     "5406716417105627", "2152306408779744",
     "4352402055428422", "7171953935869933",
     "5272176371413734", "3326240528363988", };
  ubintvec add2(add2sv);
  // sub2:
#if 0 //set to 1 if we allow b>a in subtraction
  std::vector<std::string>  sub2sv = 
    {"18446230400667224908", "0059047093523014",
     "1661936831136476", "2970884463059287",
     "0466868338124838", "18446445579403106561",
     "1640853664009664", "1040158161418506",
     "18446165366977018045", "18446477211996511393",
     "1202588881034661", "1912733630447884",
     "18443143169959719952", "0694453087476577",
     "18446058765570457758", "18445820659315544014", };

#else
  std::vector<std::string>  sub2sv = 
    {"0000000000000000", "0059047093523014",
     "1661936831136476", "2970884463059287",
     "0466868338124838", "0000000000000000",
     "1640853664009664", "1040158161418506",
     "0000000000000000", "0000000000000000",
     "1202588881034661", "1912733630447884",
     "0000000000000000", "0694453087476577",
     "0000000000000000", "0000000000000000", };

#endif
  ubintvec sub2(sub2sv);

  // mul2:
  std::vector<std::string>  mul2sv = 
    {"00129453542664913267883213339565",
     "00003938631422102517149330983287",
     "06419402382707574566639285895756",
     "04179138330699238739092142453840",
     "01660525522714165323210462878683",
     "00058575501928512376649634356636",
     "09290565704012341618368342178425",
     "12051509297159015143330318631680",
     "00132773293878034164433437538530",
     "00305578516062424854278036474730",
     "06946590599552827582889547919552",
     "00243468234057004000432166157020",
     "01494223959136453394722407100297",
     "12738664541883618180978992446890",
     "06831549111446250063725117624648",
     "02552795477367678807574345368435", };
  ubintvec mul2(mul2sv);


  ubintvec c2;
  ubintvec d2;

  // test math for case 

  c2 = a2.Add(b2);
  EXPECT_EQ (c2, add2) << "Failure 2 limb vector vector Add()";
  c2 = a2 + b2;
  EXPECT_EQ (c2, add2) << "Failure 2 limb vector vector +";
  d2 = a2;
  d2+=b2;
  EXPECT_EQ (d2, add2) << "Failure 2 limb vector vector +=";


  c2 = a2.Sub(b2);
  EXPECT_EQ (c2, sub2) << "Failure 2 limb vector vector Sub()";
  c2 = a2 - b2;
  EXPECT_EQ (c2, sub2) << "Failure 2 limb vector vector -";
  d2 = a2;
  d2 -= b2;
  EXPECT_EQ (d2, sub2) << "Failure 2 limb vector vector -=";

  c2 = a2.Mul(b2);
  EXPECT_EQ (c2, mul2) << "Failure 2 limb vector vector Mul()";
  c2 = a2 * b2;
  EXPECT_EQ (c2, mul2) << "Failure 2 limb vector vector *";
  d2 = a2;
  d2 *= b2;
  EXPECT_EQ (d2, mul2) << "Failure 2 limb vector vector *=";

}


TEST(UTubintvec,basic_vector_scalar_mod_math_2_limb){
  //basic vector scalar mod math
  //todo this is very simple, should probably add sub mul by bigger numbers.

  // q2:
  ubint q2("4057816419532801");
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  
  ubintvec a2(a2sv);
  ubintvec a2op1(a2.size());
  ubintvec a2op1test(a2.size());
  
  ubint myone(ubint::ONE);
  
  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]+myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModAdd(myone, q2);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Add()"; 

  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]-myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModSub(myone, q2);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Sub()"; 

  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]*myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModMul(myone, q2);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Mul()"; 

}


TEST(UTubintvec,basic_vector_vector_mod_math_2_limb){

  // q2:
  ubint q2("4057816419532801");
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  ubintvec a2(a2sv);

  // b2:
  std::vector<std::string>  b2sv = 
    {"0698898215124963", "0039832572186149",
     "1835473200214782", "1041547470449968",
     "1076152419903743", "0433588874877196",
     "2336100673132075", "2990190360138614",
     "0754647536064726", "0702097990733190",
     "2102063768035483", "0119786389165930",
     "3976652902630043", "3238750424196678",
     "2978742255253796", "2124827461185795", };

  ubintvec b2(b2sv);

  // modadd2:
  std::vector<std::string>  modadd2sv = 
    {"0884123387923218", "0138712237895312",
     "1275066812033239", "0996162984426422",
     "2619173177932324", "0568683443309337",
     "2255238590741013", "2962722462162933",
     "0930588339595881", "1137334268426157",
     "1348899997572826", "2152306408779744",
     "0294585635895621", "3114137516337132",
     "1214359951880933", "3326240528363988", };
  ubintvec modadd2(modadd2sv);

  // modsub2:
  std::vector<std::string>  modsub2sv = 
    {"3544143377206093", "0059047093523014",
     "1661936831136476", "2970884463059287",
     "0466868338124838", "3759322113087746",
     "1640853664009664", "1040158161418506",
     "3479109686999230", "3790954706492578",
     "1202588881034661", "1912733630447884",
     "0456912669701137", "0694453087476577",
     "3372508280438943", "3134402025525199", };
  ubintvec modsub2(modsub2sv);

  // modmul2:
  std::vector<std::string>  modmul2sv = 
    {"0585473140075497", "3637571624495703",
     "1216097920193708", "1363577444007558",
     "0694070384788800", "2378590980295187",
     "0903406520872185", "0559510929662332",
     "0322863634303789", "1685429502680940",
     "1715852907773825", "2521152917532260",
     "0781959737898673", "2334258943108700",
     "2573793300043944", "1273980645866111", };
  ubintvec modmul2(modmul2sv);

  ubintvec c2;

  //now Mod operations
  c2 = a2.ModAdd(b2,q2);
  EXPECT_EQ (c2, modadd2) << "Failure 2 limb vector vector ModAdd()";    
  
  c2 = a2.ModSub(b2,q2);
  EXPECT_EQ (c2, modsub2) << "Failure 2 limb vector vector ModSub()";   
  
  c2 = a2.ModMul(b2,q2);
  EXPECT_EQ (c2, modmul2) << "Failure 2 limb vector vector ModMul()";   

  c2 = a2.Add(b2);
  c2 %= q2;
  EXPECT_EQ (c2, modadd2) << "Failure 2 limb vector scalar %";   

  
}
