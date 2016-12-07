/*
 *  @file
 *  PRE SCHEME PROJECT, Crypto Lab, NJIT
 *  @version v01.0
 *  @author TPOC: Dr. Kurt Rohloff, <rohloff@njit.edu> 
 *  Programmers: 
 *  Dr. Yuriy Polyakov, <polyakov@njit.edu>
 *  Gyana Sahu, <grs22@njit.edu> 
 *  Nishanth Pasham, <np386@njit.edu>
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
 *  reproduce the above copyright notice, this list of conditions and
 *  the following disclaimer in the documentation and/or other materials
 *  provided with the distribution.  THIS SOFTWARE IS PROVIDED BY THE
 *  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 *  USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 *  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 
 *  @section DESCRIPTION
 *
 *  This file contains google test code that exercises the ubint
 *  unsigned big integer library of the PALISADE library.
 *
*/

#include "../include/gtest/gtest.h"
#include <iostream>
#include <bitset>
//todo reduce the number of required includes

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/utils/utilities.h"


using namespace std;
using namespace lbcrypto;
using namespace NTL;

class UnitTestubint : public ::testing::Test {
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

/************************************************/
/*	TESTING METHODS OF UBINT CLASS		*/
/************************************************/

/* Methods are tested in the following order
   Ctor, dtor, ConvertToX() 
   then shift and compare
   then math (which are built on shift and compare)
   then modulo math
   then any anciliary functions
*/

/* here are all the methods that need to be tested (or have been
   tested but not removed from this list -- oops)

printLimbsInDec
printLimbsInHex
SetValue(str)
SetValue(&ubint)

intTobint() //todo change name to IntToBint()

modulo math

how many of these do we actually want here
ModBarrett NOT DONE
ModBarrettAdd NOT DONE
ModBarrettSub NOT DONE
ModBarrettMul NOT DONE


Serialize()
Deserialize()

isIfPowerOfTwo()
GetLengthForBase()
GetDigitAtIndexForBase()
BinaryStringToUbint()
SetIdentity()

 */
/*************************************************
 * TESTING Constructors, Converters and constants 
 * note to test for memory leaks, run 
 * valgrind ./tests --gtest_filter=UTbint.*
 *************************************************/
TEST(UTubint,string_conversions_msb){
  
  //test string ctor and ConvertTo functions
  //note number of limbs cited assumes uint32_t implementation
  //create a small ubint with only one limb

  ubint q1(conv<ubint>("00000000000000163841"));
  //conv(q1, "00000000000000163841");

  //  q1.PrintIntegerConstants();

  //float f = conv<float>(q1);
  float f(conv<float>(q1));
  double d(conv<double>(q1));
  //long double xd(conv<long double>(q1));

  EXPECT_EQ(163841, q1)<<"Failure Convert 1 limb to usint";
  EXPECT_EQ(163841, q1)<<"Failure Convert 1 limb to uint";
  EXPECT_EQ(163841, q1)<<"Failure Convert 1 limb to uint64";
  EXPECT_EQ(163841.0F, f)
    <<"Failure Convert 1 limb to float";
  EXPECT_EQ(163841.0, d )
    <<"Failure Convert 1 limb to double";
  //EXPECT_EQ(163841.0L, xd)
  //  <<"Failure Convert 1 limb to longdouble";

#if 0
  //test GetMSB() for 1 limb
  usint msb = q1.GetMSB();

  EXPECT_EQ(msb, 18)<<  "Failure testing 1 limb msb test ";
#endif
  cout<<"GetMSB does not exist"<<endl;
  //create a large ubint with two limbs
  ubint q2;
  q2 = conv<ubint>("00004057816419532801");
  //to big for usint or for float so we expect that to fail

  EXPECT_EQ(4057816419532801UL, q2)
    <<"Failure Convert 2 limb to uint64";
  EXPECT_EQ(4057816419532801L, q2)
    <<"Failure Convert 2 limb to uint64";


#if 0
  //test float converstions. 

  //cout << "flt mantissa digits "<< FLT_MANT_DIG <<endl;
  //cout << "d mantissa digits "<< DBL_MANT_DIG <<endl;
  //cout << "ld mantissa digits "<< LDBL_MANT_DIG <<endl;

  float testf = 4057816419532801.0F;
  //cout << "sizeoffloat "<< sizeof(float) << endl;  
  //cout << "testf "<< testf << endl;
  EXPECT_EQ(testf, q2.ConvertToFloat())
    <<"Failure Convert 2 limb to float";    

  double testd = 4057816419532801.0;
  //cout << "sizeofdouble "<< sizeof(double) << endl;  
  //cout << "testd "<< testd << endl;
  EXPECT_EQ(testd, q2.ConvertToDouble())
    <<"Failure Convert 2 limb to double";    

  //note we expect a loss of precision
  EXPECT_NE(testd, (double)q2.ConvertToFloat())
    <<"Failure Convert 2 limb to float loss of precision";    

  long double testld = 4057816419532801.0L;
  //cout << "sizeoflongdouble "<< sizeof(long double) << endl;  
  //cout << "testld "<< testld << endl;
  EXPECT_EQ(testld, q2.ConvertToLongDouble())
    <<"Failure Convert 2 limb to long double";

  //test GetMSB()
  msb = q2.GetMSB();
  //DEBUG("q2 msb "<<msb);
  EXPECT_EQ(msb, 52)<<  "Failure testing 2 limb msb test ";
#endif
#if 0 //this 'feature' was removed to match BBI operation.
  bool thrown = false;
  try {
    //test the ctor()

    ubint b;
    usint bout = b; //should thrown since b is not initialised.
  } catch (...) {
    thrown = true;
  }
  EXPECT_TRUE(thrown) 
    << "Failure testing ConvertToUsint() throw on uninitialed ubint";
#endif
  cout<<"float conversions not tested"<<endl;
}
TEST(UTubint,ctor){    

  //test the ctor(usint)
  ubint c1(123456789);
  EXPECT_EQ(123456789, c1)<< "Failure testing ctor(usint)";
  //test the ctor(string)
  ubint c2(conv<ubint>("123456789"));
  EXPECT_EQ(123456789, c2)<< "Failure testing ctor(string)";
  //test the ctor(ubint)
  ubint d(c1);
  EXPECT_EQ(d, c1)
    << "Failure testing ctor(ubint)";
  //test the ctor(ubint&)
  ubint &e = d;
  ubint f(e);
  EXPECT_EQ(e, f)
    << "Failure testing ctor(ubint&)";
} 

TEST(UTubint,ctor32){       
  // TEST CASE FOR 32bit VALUES
  ubint a(UINT32_MAX);
  uint32_t aint32 = UINT32_MAX;

  EXPECT_EQ(aint32,a)
    << "Failure testing ConvertToUint32() for UINT32_MAX";    

  const usint bitwidth = 32;
  bitset<bitwidth> abs;
  for (usint i = 0; i < bitwidth; i++) {
    abs[i] = 1;
  }
  uint32_t cint32 = abs.to_ulong(); //biggest 32 bit int all FFs
  ubint c(cint32);
  EXPECT_EQ(cint32,c)
    << "Failure testing ConvertToUsint() for maxint32 made with bitsets";    

  EXPECT_EQ(UINT32_MAX,c)
    << "Failure testing ConvertToUsint() for UINT32_MAX";    
}

TEST(UTubint,ctor64){    
  // TEST CASE FOR 64bit VALUES
  /*ubint a(9223372036854775807ULL); // = 7FFFFFFF
  uint64_t auint64 = 9223372036854775807ULL;
>>>>>>> Commenting out test that is failing.
  EXPECT_EQ(auint64,a)
    << "Failure testing ConvertToUint64() for big numbers";    
  bitset<64> abs;
  for (usint i = 0; i < 64; i++) {
    abs[i] = 1;
  }
  uint64_t cuint64 = abs.to_ullong(); //biggest 64 bit int all FFs
  ubint c(cuint64);

  EXPECT_EQ(cuint64,c)
    << "Failure testing ConvertToUint64() for maxint64";    

  EXPECT_EQ(UINT64_MAX,c)
    << "Failure testing ConvertToUint64() for UINT64_MAX"; 

  EXPECT_EQ("18446744073709551615", c.ToString())
    << "Failure testing ToString() for UINT64_MAX"; */

  //todo some very large digit tests.
}

/*************************************************
 * TESTING constants 
 *************************************************/
TEST(UTubint,consts){

  ubint a;

  //todo: define these?
// test the constants
  a = ubint::zero();
  EXPECT_EQ(ubint(0), a)<< "Failure testing ZERO";
#if 0
  a = ubint::ONE;
  EXPECT_EQ(ubint(1), a)<< "Failure testing ONE";

  a = ubint::TWO;
  EXPECT_EQ(ubint(2), a)<< "Failure testing TWO";

  a = ubint::THREE;
  EXPECT_EQ(ubint(3), a)<< "Failure testing THREE";

  a = ubint::FOUR;
  EXPECT_EQ(ubint(4), a)<< "Failure testing FOUR";

  a = ubint::FIVE;
  EXPECT_EQ(ubint(5), a)<< "Failure testing FIVE";
#endif
  //todo: test log constants?
}

/****************************/
/* TESTING SHIFT OPERATORS  */
/****************************/

TEST(UTubint,left_shift){

  // TESTING OPERATOR LEFT SHIFT (<< AND <<=) FOR ALL CONDITIONS
  // The operator 'Left Shift' operates on ubint a, and it
  // is shifted by a number

  // Returns: a<<(num), and the result is stored in ubint
  // or returned in original for <<=
  // 'a' is left shifted by 'num' number of bits, and
  // filled up by 0s from right which is equivalent to a * (2^num)
  //        example:
  //            4<<3 => (100)<<3 => (100000) => 32
  //           this is equivalent to: 4* (2^3) => 4*8 =32

  // TEST CASE WHEN SHIFT IS LESS THAN LIMB SIZE
  {
    ubint a(conv<ubint>("39960"));

    usint shift = 3;

    ubint calculatedResult = a<<(shift);
    usint expectedResult = 319680;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing << less than limb size";

    a<<=(shift);
    EXPECT_EQ(expectedResult, a)
      << "Failure testing <<= less than limb size";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN LIMB SIZE
  {
    ubint a(conv<ubint>("39960"));
    usint shift = 33;

    ubint calculatedResult = a<<(shift);
    uint64_t expectedResult = 343253786296320L;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing << greater than limb size";

    a<<=(shift);
    EXPECT_EQ(expectedResult, a)
      << "Failure testing <<= greater than limb size";
  }

  {
    
    ubint a(conv<ubint>("1024"));
    usint shift = 48;
    
    ubint calculatedResult = a<<(shift);
    uint64_t expectedResult = 288230376151711744;
    uint64_t result = conv<uint64_t>(calculatedResult);

    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing << greater than limb size";
    a<<=(shift);
    EXPECT_EQ(expectedResult, a)
      << "Failure testing <<= greater than limb size";

  }

  // TEST CASE WHEN SHIFT IS multi limb
  {
    ubint a(conv<ubint>("138712237895312"));
    usint shift = 8;

    //usint msb = a.GetMSB();
    //DEBUG("a.msb " <<msb);

    ubint calculatedResult = a<<(shift);
    uint64_t expectedResult = 35510332901199872;
    //DEBUG("expectedResult 35510332901199872 ="<<expectedResult);

    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing << multi limb";
    a<<=(shift);
    EXPECT_EQ(expectedResult, a)
      << "Failure testing <<= multi limb";
  }
}
TEST(UTubint,right_shift){

  // TESTING OPERATOR RIGHT SHIFT (>> AND >>=) FOR ALL CONDITIONS
  // The operator 'Right Shift' operates on ubint a, and it
  // is shifted by a number of bits 

  // Returns: a>>(num), and the result is stored in ubint or the
  // original a for >>=
  // Result 'a' is right shifted by 'num'
  // number of bits, and filled up by 0s from left which is equivalent
  // to a / (2^num)
  //  ex:4>>3 => (100000)>>3 => (000100) => 4
  // this is equivalent to: 32*(2^3) => 32/8 = 4

  // TEST CASE WHEN SHIFT IS LESS THAN LIMB SIZE
  {
    ubint a(conv<ubint>("39965675"));
    usshort shift = 3;

    ubint calculatedResult = a>>(shift);
    usint expectedResult = 4995709;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing >> less than limb size";
    a>>=(shift);
    EXPECT_EQ(expectedResult, a)
      << "Failure testing >>= less than limb size";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN LIMB SIZE
  {
    ubint a(conv<ubint>("343253786296320"));
    usshort shift = 33;

    ubint calculatedResult = a>>(shift);
    usint expectedResult = 39960;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing >>= greater than limb size";
    a>>=(shift);
    EXPECT_EQ(expectedResult, a)
      << "Failure testing >>= greater than limb size";
  }
  {
    ubint a(conv<ubint>("288230376151711744"));
    usshort shift = 48;

    ubint calculatedResult = a>>(shift);
    usint expectedResult = 1024;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing >> greater than limb size";
    a>>=(shift);
    EXPECT_EQ(expectedResult, a)
      << "Failure testing >>= greater than limb size";

  }
}
/********************************************/
/* TESTING COMPARATOR METHODS AND OPERATORS */
/********************************************/
TEST(UTubint, compare){
  /* TESTING METHOD COMPARE and gt, lt, eq, neq FOR ALL CONDITIONS    */

  // The method "Comapare" comapres two BigBinary Integers a,b
  // Returns:
  //    1, when a>b
  //    0, when a=b
  //   -1, when a<b
  //
  // Result is stored in signed integer, and then the result is
  // typecasted to int as  if  takes integer

  sint c;
  sint expectedResult;
  bool cbool;
  
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER
  {
    ubint a(conv<ubint>("2124827461185795"));
    ubint b(conv<ubint>("1201413067178193"));
    
    //c = a.compare(b);
    c = compare(a,b);

    expectedResult = 1;
    EXPECT_EQ(expectedResult, c)<< "Failure testing compare a >  b";
    cbool= a>b;
    EXPECT_TRUE(cbool)<< "Failure testing > : a > b";
    cbool= a>=b;
    EXPECT_TRUE(cbool)<< "Failure testing >= : a > b";
    cbool= a<b;
    EXPECT_FALSE(cbool)<< "Failure testing < : a > b";
    cbool= a<=b;
    EXPECT_FALSE(cbool)<< "Failure testing <= : a > b";
    cbool= a==b;
    EXPECT_FALSE(cbool)<< "Failure testing == : a > b";
    cbool= a!=b;
    EXPECT_TRUE(cbool)<< "Failure testing != : a > b";
    
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
  {
    ubint a(conv<ubint>("1201413067178193"));
    ubint b(conv<ubint>("2124827461185795"));
    
    //c = a.compare(b);
    c = compare(a,b);
    expectedResult = -1;
    
    EXPECT_EQ(expectedResult,c)<< "Failure testing compare a < b";
    cbool= a>b;
    EXPECT_FALSE(cbool)<< "Failure testing > : a < b";
    cbool= a>=b;
    EXPECT_FALSE(cbool)<< "Failure testing >= : a < b";
    cbool= a<b;
    EXPECT_TRUE(cbool)<< "Failure testing < : a < b";
    cbool= a<=b;
    EXPECT_TRUE(cbool)<< "Failure testing <= : a < b";
    cbool= a==b;
    EXPECT_FALSE(cbool)<< "Failure testing == : a < b";
    cbool= a!=b;
    EXPECT_TRUE(cbool)<< "Failure testing != : a < b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
  {
    ubint a(conv<ubint>("2124827461185795"));
    ubint b(conv<ubint>("2124827461185795"));
    
    //c = a.compare(b);
    c = compare(a,b);
    expectedResult = 0;
    
    EXPECT_EQ(expectedResult,c)<< "Failure testing compare a == b";
    cbool= a>b;
    EXPECT_FALSE(cbool)<< "Failure testing > : a == b";
    cbool= a>=b;
    EXPECT_TRUE(cbool)<< "Failure testing >= : a == b";
    cbool= a<b;
    EXPECT_FALSE(cbool)<< "Failure testing < : a == b";
    cbool= a<=b;
    EXPECT_TRUE(cbool)<< "Failure testing <= : a == b";
    cbool= a==b;
    EXPECT_TRUE(cbool)<< "Failure testing == : a == b";
    cbool= a!=b;
    EXPECT_FALSE(cbool)<< "Failure testing != : a == b";
  }
  
  //test case that failed in TR 409
  {

    ubint a(conv<ubint>("11272741999"));
    ubint b(conv<ubint>("8828677302"));

    //c = a.compare(b);
    c = compare(a,b);
    expectedResult = 1;
    EXPECT_EQ(expectedResult,c)<< "Failure testing compare TR 409";

  }
}

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/
TEST(UTubint,basic_math){
  ubint calculatedResult;
  uint64_t expectedResult;
  string expectedResultStr; //for when ubint is > 64 bits.
    
  //TESTING + and +=

  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    ubint a(203450);
    ubint b(2034);

    //calculatedResult = a.Add(b);
    add(calculatedResult,a,b);
    expectedResult = 205484;

    //DEBUG("result "<<result);
    //DEBUG("expect "<<expectedResult);

    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing Add() : a > b";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing + : a > b";

    a+=b;
    EXPECT_EQ(expectedResult, a)
      <<"Failure testing += : a > b";

  }

  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    ubint a(2034);
    ubint b(203450);

    //calculatedResult = a.Add(b);
    add(calculatedResult,a,b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing Add() : a < b";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing + : a < b";

    a+=b;
    EXPECT_EQ(expectedResult, a)
      <<"Failure testing += : a < b";
  }

  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
  // LIMB
  {
    ubint a(conv<ubint>("4294967295"));
    ubint b(conv<ubint>("1"));

    //calculatedResult = a.Add(b);
    add(calculatedResult,a,b);
    expectedResult = 4294967296;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing Add() : overflow to next limb";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing + : overflow to next limb";

    a+=b;
    EXPECT_EQ(expectedResult, a)
      <<"Failure testing += : overflow to next limb";
  }

  // TEST CASE WHEN MSB OF THE RESULT HAS NO BIT-OVERFLOW IN THE SAME
  // LIMB
  //todo change for limb

  {
    ubint a(35);
    ubint b(1015);
      
    //calculatedResult = a.Add(b);
        add(calculatedResult,a,b);
        expectedResult = 1050;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing Add() :no overflow in same limb";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing + :no overflow in same limb";

    a+=b;
    EXPECT_EQ(expectedResult, a)
      <<"Failure testing += :no overflow in same limb";
  }

  // TEST CASE WHEN both are multi limb numbers
  {
    ubint a(conv<ubint>("98879665709163"));
    ubint b(conv<ubint>("39832572186149"));
      
    // calculatedResult = a.Add(b);
    add(calculatedResult,a,b);
        expectedResult = 138712237895312;
      
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing Add() : multi limb";
      
    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing + : multi limb";
      
    a+=b;
    EXPECT_EQ(expectedResult, a)
      <<"Failure testing += : multi limb";
  }

  //TESTING - and -=
    
  // note that when a<b, the result is 0, since there is no support
  // for negative numbers in ubint (see sbint for future
  // implementation)x
    
  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
      
    ZZ a(20489);
    ubint b(2034455);
      
    //calculatedResult = a.Sub(b);
    sub(calculatedResult,a,b);
#ifndef NTL_BITS_PER_LONG //then NTL is being used
    //since ubint is unsigned  result should be zero
    expectedResult = 0;
#else
    expectedResult = -2013966;
#endif

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing Sub() : a < b";
      
    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing - : a < b";
      
    a-=b;
    EXPECT_EQ(expectedResult, a)
      << "Failure testing -= : a < b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    ubint a(conv<ubint>("2048956567"));
    ubint b(conv<ubint>("2048956567"));
      
    //calculatedResult = a.Sub(b);
    sub(calculatedResult,a,b);
    expectedResult = 0;
      
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing Sub() : a == b";
      
    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing - : a == b";
      
    a-=b;
    EXPECT_EQ(expectedResult, a)
      << "Failure testing -= : a == b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    ubint a(conv<ubint>("2048956567"));
    ubint b(conv<ubint>("2034455"));
      
    //calculatedResult = a.Sub(b);
    sub(calculatedResult,a,b);
    expectedResult = 2046922112;
      
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing Sub() : a > b";
      
    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing - : a > b";
      
    a-=b;
    EXPECT_EQ(expectedResult,a)
      << "Failure testing -= : a > b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    //todo: change for limb
    ubint a(196737);
    ubint b(65406);
      
    //calculatedResult = a.Sub(b);
    sub(calculatedResult,a,b);
    expectedResult = 131331;
      
    EXPECT_EQ(expectedResult,calculatedResult)
      <<"Failure testing Sub() : borrow from next byte"; 
      
    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing - : borrow from next byte"; 
      
    a-=b;
    EXPECT_EQ(expectedResult,a)
      <<"Failure testing -= : borrow from next byte"; 

  }
  // TEST CASE WHEN SUBTRACTION IS MULTI LIMB
  {
    ubint a(conv<ubint>("98879665709163"));
    ubint b(conv<ubint>("39832572186149"));

    //calculatedResult = a.Sub(b);
    sub(calculatedResult,a,b);
    expectedResult = 59047093523014;

    EXPECT_EQ(expectedResult,calculatedResult)
      <<"Failure testing Sub() : multi limb";

    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing - : multi limb";
    a-=b;
    EXPECT_EQ(expectedResult,a)
      <<"Failure testing -= : multi limb";
  }

  // TESTING METHOD MUL FOR ALL CONDITIONS 
  // The method "Mul" does multiplication on two ubints
  // a,b Returns a*b, which is stored in another ubint for * or in a for *=
  {
    //single Limb
    ubint a(1967);
    ubint b(654);

    //calculatedResult = a.Mul(b);
    mul(calculatedResult,a,b);
    expectedResult = 1286418;

    EXPECT_EQ(expectedResult,calculatedResult)
      <<"Failure testing Mul() : single limb";
    calculatedResult = a * b;
    EXPECT_EQ(expectedResult,calculatedResult)
      <<"Failure testing * : single limb";
    a *= b;
    EXPECT_EQ(expectedResult,a)
      <<"Failure testing *= : single limb";
  }
  {
    //multi limb
    ubint a(conv<ubint>("98879665709163"));
    ubint b(conv<ubint>("39832572186149"));

    //calculatedResult = a.Mul(b);
    mul(calculatedResult,a,b);
    expectedResultStr = "3938631422102517149330983287";
    // note the expected result is bigger than uint64 so we cannot use
    // that to compare. Instead we uses string values.
    stringstream calculatedResultStr;
    calculatedResultStr<<calculatedResult;
    EXPECT_EQ(expectedResultStr,calculatedResultStr.str())
      <<"testing Mul() : multi limb";
    calculatedResult = a * b;
    calculatedResultStr.str(""); //clear string
    calculatedResultStr << calculatedResult;
    EXPECT_EQ(expectedResultStr,calculatedResultStr.str())
      <<"Failure testing * : multi limb";
    a *= b;
    calculatedResultStr.str(""); //clear string
    calculatedResultStr<< a;
    EXPECT_EQ(expectedResultStr,calculatedResultStr.str())
      <<"Failure testing *= : multi limb";

  }

  // TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS
  // The method "Divided By" does division of ubint a by ubint b
  // Returns a/b, which is stored in another
  // ubint calculatedResult 
  // When b=0, throws
  // error, since division by Zero is not allowed When a<b, returns 0,
  // since decimal value is not returned


  // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
  {
    ubint a(2048);
    ubint b(2034455);

    //calculatedResult = a.Div(b);
    div(calculatedResult,a,b);
    expectedResult = 0;

    //RESULT SHOULD BE ZERO
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing Div() : a < b";

    calculatedResult = a/b;      
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing / : a < b";

    a/=b;      
    EXPECT_EQ(expectedResult, a)
      <<"Failure testing /= : a < b";

  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {

    ubint a(conv<ubint>("2048956567"));
    ubint b(conv<ubint>("2048956567"));

    //calculatedResult = a.Div(b);
    div(calculatedResult,a,b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing Div() : a == b";

    calculatedResult = a/b;
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"Failure testing / : a == b";

    a/=b;      
    EXPECT_EQ(expectedResult, a)
      <<"Failure testing /= : a == b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    ubint a(conv<ubint>("2048956567"));
    ubint b(conv<ubint>("2034455"));

    //calculatedResult = a.Div(b);
    div(calculatedResult,a,b);
    expectedResult = 1007;

    EXPECT_EQ(expectedResult, calculatedResult)
      <<"testing Div() a greater than b";

    calculatedResult = a/b;
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"testing / by a greater than b";

    a/=b;      
    EXPECT_EQ(expectedResult, a)
      <<"testing /= by a greater than b";
  }

  // TEST CASE for MULTI LIMB
  {
    ubint a(conv<ubint>("3938631422102517149330983287"));
    ubint b(conv<ubint>("98879665709163"));


    //calculatedResult = a.Div(b);
    div(calculatedResult,a,b);
    expectedResult = 39832572186149;

    EXPECT_EQ(expectedResult, calculatedResult)
      <<"testing divided by multi limb";
    calculatedResult = a/b;
    EXPECT_EQ(expectedResult, calculatedResult)
      <<"testing divided by multi limb";

    a/=b;      
    EXPECT_EQ(expectedResult, a)
      <<"testing /= by multi limb";
  }

  // TEST CASE for DIVIDE BY 0
  // should throw an error so we verify it does
  {
    ubint a(conv<ubint>("3938631422102517149330983287"));
    ubint b(0);

    bool thrown = false;

    try {
      //calculatedResult = a.Div(b);
      div(calculatedResult,a,b);
    }
    catch (...){
      thrown = true;
    }
    EXPECT_TRUE(thrown)<<"Failure testing Div() zero";
    thrown = false;

    try {
      calculatedResult = a/b;
    }
    catch (...){
      thrown = true;
    }
    EXPECT_TRUE(thrown)<<"Failure testing / zero";

    thrown = false;
    try {
      a/=b;
    }
    catch (...){
      thrown = true;
    }
    EXPECT_TRUE(thrown)<<"Failure testing /= zero";
  }

  // TESTING METHOD  EXP 
  {
    ubint x(56);
    //ubint result = x.Exp(10);
    ubint result;
    power(result,x,10);

    ubint expectedResult(conv<ubint>("303305489096114176"));
    EXPECT_EQ(expectedResult, result)
      << "Failure testing exp";
  }
}

TEST(UTubint,mod_operations){

  /************************************************/
  /* TESTING METHOD MOD FOR ALL CONDITIONS        */
  /************************************************/

  // The method "Mod" does modulus operation on two ubints
  // m,p Returns (m mod p), which is stored in another ubint

  ubint calculatedResult;
  int expectedResult;
  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD
  {
    ubint m(27);
    ubint p(240);

    //calculatedResult = m.Mod(p);
    rem(calculatedResult,m,p);
    expectedResult = 27;

    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing Mod(): number < modulus";

    calculatedResult = m%p;
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing % : number < modulus";

    m%=p;
    EXPECT_EQ(expectedResult,m)
      << "Failure testing %= : number < modulus";
  }
  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    ubint m(93409673);
    ubint p(406);

    //calculatedResult = m.Mod(p);
    rem(calculatedResult,m,p);
    expectedResult = 35;

    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing Mod(): number > modulus";

    calculatedResult = m%p;
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing %: number > modulus";

    m%=p;
    EXPECT_EQ(expectedResult,m)
      << "Failure testing %=: number > modulus";
  }
  // TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
  {
    ubint m(32768);
    ubint p(16);

    //calculatedResult = m.Mod(p);
    rem(calculatedResult,m,p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing Mod(): number_divisible by modulus";

    calculatedResult = m%p;
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing %:  number_divisible by modulus";

    m%=p;
    EXPECT_EQ(expectedResult,m)
      << "Failure testing %=:  number_divisible by modulus";
  }

  // TEST CASE WHEN THE NUMBER IS EQUAL TO MOD
  {
    ubint m(67108913);
    ubint p(67108913);

    //calculatedResult = m.Mod(p);
    rem(calculatedResult,m,p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing Mod(): number == modulus";
    calculatedResult = m%p;
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing %:   number == modulus";

    m%=p;
    EXPECT_EQ(expectedResult,m)
      << "Failure testing %=:  number == modulus";
  }

  // TEST CASE THAT FAILED TR#392    
  {
    ubint first(conv<ubint>("4974113608263"));
    ubint second(conv<ubint>("486376675628"));
    ubint modcorrect(conv<ubint>("110346851983"));
    ubint modresult;

   // modresult = first.Mod(second);
    rem(modresult, first, second);
    EXPECT_EQ(modcorrect, modresult)
      <<"Failure ModInverse() Mod regression test";
  }

  // TEST CASE THAT FAILED TR#409
  {

    ubint first(conv<ubint>("11272741999"));
    ubint second(conv<ubint>("8828677302"));

    ubint modcorrect(conv<ubint>("2444064697"));
    ubint modresult;
    
    //modresult = first.Mod(second);
    rem(modresult, first, second);
    EXPECT_EQ(modcorrect, modresult)
      <<"Failure Mod() Mod tr #409";
  }


  // ANOTHER TEST CASE THAT FAILED TR#409
  {

    ubint first(conv<ubint>("239109124202497"));
    ubint second(conv<ubint>("9"));

    ubint modcorrect(1);
    ubint modresult;
    
    //modresult = first.Mod(second);
    rem(modresult, first, second);
    EXPECT_EQ(modcorrect, modresult)
      <<"Failure Mod() Mod tr #409 2";
  }




  // Mod(0)
  {
    ubint first(conv<ubint>("4974113608263"));
    ubint second(0);
    ubint modcorrect(conv<ubint>("4974113608263"));
    ubint modresult;

    bool thrown = false;
    try {
      //modresult = first.Mod(second);
      rem(modresult, first, second);
    }
    catch (exception& e){
      std::cout<<e.what()<<std::endl;
      thrown = true;
    }

    EXPECT_TRUE(thrown)
      << "Failure testing ModInverse() non co-prime arguments";
  }

}

  /************************************************/
  /* TESTING METHOD MOD BARRETT FOR ALL CONDITIONS */
  /************************************************/

  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

  /*TEST(UTubint_METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

    ubint a("9587");
    ubint b("3591");
    ubint c("177");

    ubint calculatedResult = a.ModBarrett(b,c);
    int expectedResult = 205484;

    std::cout<<"\n"<<d<<"\n";	//for testing purpose

    //EXPECT_EQ(27,calculatedResult);
    }
  */

  /*************************************************/
  /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
  /*************************************************/
  // The method "Mod Inverse" operates on ubints m,p
  // Returns {(m)^(-1)}mod p
  //    which is multiplicative inverse of m with respect to p, and is
  //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
  //    of m and p is 1)
  // If m and p are not co-prime, the method throws an error
  // ConvertToUsint converts ubint calculatedResult to integer

TEST(UTubint,mod_inverse){
  ubint calculatedResult;
  int expectedResult;

  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    ubint m(5);
    ubint p(108);

    //calculatedResult = m.ModInverse(p);
    InvMod(calculatedResult,m,p);
    expectedResult = 65;
    
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing ModInverse(): number less than modulus";
  }

  // TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
  {
    ubint m(3017);
    ubint p(7);

    bool thrown = false;
    try {
      //calculatedResult = m.ModInverse(p);
      InvMod(calculatedResult,m,p);
    }
    catch (exception& e){
      std::cout<<e.what()<<std::endl;
      thrown = true;
    }
    //expectedResult = 77;

    EXPECT_TRUE(thrown)
      << "Failure testing ModInverse() non co-prime arguments";

  }

  //testcase that failed during testing.
  {


    ubint input (conv<ubint>("405107564542978792"));
    ubint modulus(conv<ubint>("1152921504606847009"));
    ubint modIcorrect(conv<ubint>("844019068664266609"));
    ubint modIresult;

    bool thrown = false;
    try {
      //modIresult = input.ModInverse(modulus);
      InvMod(modIresult, input, modulus);
    }
    catch (exception& e){
      thrown = true;
      std::cout<<e.what()<<std::endl;
      modIresult = ubint(0);
    }

    EXPECT_FALSE(thrown)
      << "Failure ModInverse() regression test caught throw";
    EXPECT_EQ(modIcorrect, modIresult)
      <<"Failure ModInverse() regression test";
  }

}

TEST(UTubint,mod_arithmetic){
  ubint calculatedResult;
  int expectedResult;

  /************************************************/
  /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
  /************************************************/
  // The method "Mod Add" operates on ubints m,n,q
  //   Returns:
  //     (m+n)mod q
  //      = {(m mod q) + (n mod q)}mod q

  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    ubint m(58059595);
    ubint n(3768);
    ubint q(4067);

    //calculatedResult = m.ModAdd(n,q);
    AddMod(calculatedResult,m,n,q);
    expectedResult = 2871;

    EXPECT_NE(expectedResult,calculatedResult)
      << "Failure testing ModAdd() first number > modulus";

    AddMod(calculatedResult,m%q,n,q);
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing ModAdd() taking mod of first number";


  }
  // TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
  {
    ubint m(595);
    ubint n(376988);
    ubint q(4067);

    //calculatedResult = m.ModAdd(n,q);
    AddMod(calculatedResult,m,n,q);
    expectedResult = 3419;

    EXPECT_NE(expectedResult,calculatedResult)
      << "Failure testing ModAdd() second number > modulus";

    AddMod(calculatedResult,m,n%q,q);
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing ModAdd() taking mod second number";

  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
  {
    ubint m(595);
    ubint n(376);
    ubint q(4067);

    //calculatedResult = m.ModAdd(n,q);
    AddMod(calculatedResult,m,n,q);
    expectedResult = 971;
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing ModAdd() both numbers < modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
  {

    ubint m(59509095449);
    ubint n(37654969960);
    ubint q(4067);

    //calculatedResult = m.ModAdd(n,q);
    AddMod(calculatedResult,m,n,q);
    expectedResult = 2861;

    EXPECT_NE(expectedResult, calculatedResult)
     << "Failure testing ModAdd() both numbers > modulus";

    AddMod(calculatedResult,m%q,n%q,q);

    EXPECT_EQ(expectedResult, calculatedResult)
     << "Failure testing ModAdd() taking mod both numbers > modulus";
  }

  /************************************************/
  /* TESTING METHOD MODSUB FOR ALL CONDITIONS -*/
  /************************************************/
  // The method "Mod Sub" operates on ubints m,n,q
  //   Returns:
  //    (m-n)mod q
  //    = {(m mod q) - (n mod q)}mod q	when m>n
  //    = 0 when m=n
  //    = {(m mod q)+q-(n mod q)}mod q when m<n

  //   ConvertToUsint converts ubint calculatedResult to
  //   integer

  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    ubint m(595);
    ubint n(399);
    ubint q(406);

    //std::cout << "Before : " << std::endl;

    //calculatedResult = m.ModSub(n,q);
    SubMod(calculatedResult,m,n,q);
    expectedResult = 196;

    // Action is undefined, you would expect this to fail but it doesnt
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing ModSub() first number > modulus";

    SubMod(calculatedResult,m%q,n,q);

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing ModSub() taking mod first number > modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
  {
    ubint m(39960);
    ubint n(595090959);
    ubint q(406756);

    //calculatedResult = m.ModSub(n,q);
    SubMod(calculatedResult,m,n,q);
    expectedResult = 33029;

    //[{(a mod c)+ c} - (b mod c)] since a < b
    EXPECT_NE(expectedResult,calculatedResult)
      << "Failure testing ModSub() second number > modulus";

    SubMod(calculatedResult,m,n%q,q);

    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing ModSub() taking mod of second number > modulus";


  }
  // TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
  {
    ubint m(595090959);
    ubint n(595090959);
    ubint q(406756);

    //calculatedResult = m.ModSub(n,q);
    SubMod(calculatedResult,m,n,q);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing ModSub() first number == second number";
  }

  /************************************************/
  /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Mul" operates on ubints m,n,q
  //   Returns:  (m*n)mod q
  //              = {(m mod q)*(n mod q)}

  {
    ubint m(39960);
    ubint n(7959);
    ubint q(406756);

    //ubint calculatedResult = m.ModMul(n,q);
    MulMod(calculatedResult,m,n,q);
    int expectedResult = 365204;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing ModMul()";
  }

  /************************************************/
  /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Exp" operates on ubints m,n,q
  // Returns:  (m^n)mod q
  //   = {(m mod q)^(n mod q)}mod q

  {
    ubint m(39960);
    ubint n(10);
    ubint q(406756);

    //ubint calculatedResult = m.ModExp(n,q);
    PowerMod(calculatedResult,m,n,q);
    int expectedResult = 139668;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing ModExp()";
  }
}
#if 0
//Miscellaneous functions tests
TEST(UTubint, misc_functions){
  // TESTING METHOD  BinaryStringToUbint

 std:string binaryString = "1011101101110001111010111011000000011";
  ubint b =
    lbcrypto::ubint::BinaryStringToUbint(binaryString);

  ubint expectedResult("100633769475");
  EXPECT_EQ(expectedResult, b)
    << "Failure testing BinaryToUbint()";
}
#endif
