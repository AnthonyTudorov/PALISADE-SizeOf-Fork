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
 *  This file contains google test code that exercises the big int
 *  scalar library of the PALISADE lattice encryption library.
 *
*/

#include "../include/gtest/gtest.h"
#include <iostream>
//todo reduce the number of required includes

#include "../../src/lib/math/backend.h"
#include "../../src/lib/crypto/lwecrypt.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/utils/utilities.h"

using namespace std;
using namespace lbcrypto;

class UnitTestbint : public ::testing::Test {
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
/*	TESTING METHODS OF BININT CLASS		*/
/************************************************/
/* here are all the methods that need to be tested (or have been
   tested but not removed from this list

unary operators
=(bint)
=bint&&)
<<(usshort)
<<=(usshort)
>>(usshort)
>>=(usshort)

printValueInDec
GetMSB
SetValue

math

Add x
Sub xx
Mul x
+= x
-= x
*= NOT DONE
mod math

how many of these do we actually want here
Mod x
ModBarrett NOT DONE
ModINverse
ModAdd x
ModBarrettAdd NOT DONE
ModSub x
ModBarrettSub NOT DONE
ModMul x
ModBarrettMul NOT DONE
ModExp x


ToString
Compare 
==)bint)
checkifpoweroftwo
!=(bint)
>(bint)
>=(bint)
<(bint)
<=(bint)

GetMSB32(uint64_t)
GetMSBlimb_t(limb_t)
GetDigitAtIndexForBase
BunaryStringToBint
Exp
GetMSBDlimb_t
UintInBinaryToDecimal

<<ostream operator (check for leaks)



double_bitVal
add_bitVal
GetBitatIndex
SetINtAt INdex
inttobint



 */
/*************************************************
 * TESTING Constructor destructors and constants 
 * note to test for memory leaks, run 
 * valgrind ./tests --gtest_filter=UTbint.*
 *************************************************/
TEST(UTbint,ctor_dtor_const){


  bint a;
  // test ConvertToInt() and ConvertToDouble() as we use it a lot
  a = 123456789;
  usint ausint = 123456789;
  float afloat = 123456789.0;
  EXPECT_EQ(ausint, a.ConvertToUsint())
    << "Failure testing .ConvertToUsint()";
  EXPECT_EQ(afloat, a.ConvertToFloat())
    << "Failure testing .ConvertToFloat()";

  // test the constants
  a = bint::ZERO;
  EXPECT_EQ(0, a.ConvertToUsint())
    << "Failure testing ZERO";

  a = bint::ONE;
  EXPECT_EQ(1, a.ConvertToUsint())
    << "Failure testing ONE";

  a = bint::TWO;
  EXPECT_EQ(2, a.ConvertToUsint())
    << "Failure testing TWO";

  a = bint::THREE;
  EXPECT_EQ(3, a.ConvertToUsint())
    << "Failure testing THREE";

  a = bint::FOUR;
  EXPECT_EQ(4, a.ConvertToUsint())
    << "Failure testing FOUR";

  a = bint::FIVE;
  EXPECT_EQ(5, a.ConvertToUsint())
    << "Failure testing FIVE";

  //test the ctor()
  bint b;
  EXPECT_EQ(0, b.ConvertToUsint())
      << "Failure testing ctor()";

  //test the ctor(usint)
  bint c1(123456789);
  EXPECT_EQ(123456789, c1.ConvertToUsint())
      << "Failure testing ctor(usint)";

  //test the ctor(string)
  bint c2("123456789");
  EXPECT_EQ(123456789, c2.ConvertToUsint())
      << "Failure testing ctor(string)";


  //test the ctor(bint)
  bint d(c1);
  EXPECT_EQ(d.ConvertToUsint(), c1.ConvertToUsint())
      << "Failure testing ctor(bint)";

  //test the ctor(bint&)
  bint &e = d;
  bint f(e);
  EXPECT_EQ(e.ConvertToUsint(), f.ConvertToUsint())
      << "Failure testing ctor(bint&)";

  // TEST CASE FOR 32bit VALUES
  {
    bint a(UINT32_MAX);
    uint32_t aint32 = UINT32_MAX;

    EXPECT_EQ(aint32,a.ConvertToUint32())
      << "Failure testing ConvertToUint32() for UINT32_MAX";    

    const usint bitwidth = 32;
    bitset<bitwidth> abs;
    for (usint i = 0; i < bitwidth; i++) {
      abs[i] = 1;
    }
    uint32_t cint32 = abs.to_ulong(); //biggest 32 bit int all FFs
    bint c(cint32);
    EXPECT_EQ(cint32,c.ConvertToUsint())
      << "Failure testing ConvertToUsint() for maxint32 made with bitsets";    

    EXPECT_EQ(UINT32_MAX,c.ConvertToUsint())
      << "Failure testing ConvertToUsint() for UINT32_MAX";    

    //todo: add more tess

  }

  // TEST CASE FOR 64bit VALUES
  {
    bint a(9223372036854775807); // = 7FFFFFFF
    //todo FAILS 
    uint64_t auint64 = 9223372036854775807;

    EXPECT_EQ(auint64,a.ConvertToUint64())
      << "Failure testing ConvertToUint64() for big numbers";    

  bitset<64> abs;
  for (usint i = 0; i < 64; i++) {
    abs[i] = 1;
  }
  uint64_t cuint64 = abs.to_ullong(); //biggest 64 bit int all FFs
  bint c(cuint64);

  cout << "c " << c <<endl;
  cout << "cuint64 " << cuint64 <<endl;
  cout << "c.ToString " << c.ToString() <<endl;
  cout << "c.ConvertToUint64 " << c.ConvertToUint64() <<endl;



  EXPECT_EQ(cuint64,c.ConvertToUint64())
      << "Failure testing ConvertToUint64() for maxint64";    

  EXPECT_EQ(UINT64_MAX,c.ConvertToUint64())
      << "Failure testing ConvertToUint64() for UINT64_MAX";    

  usint bitNum_a = bint::GetMSB32(auint64);
  cout <<"bintnum_a 32 " << bitNum_a << endl;
  bitNum_a = bint::GetMSB64(auint64);
  cout <<"bintnum_a 64 "<< bitNum_a << endl;

  }

  //todo catch some failed throws for Uint32 and Usint

  //todo some very large digit tests.

  
}


/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/
TEST(UTbint,basic_math){

  /************************************************/
  /* TESTING METHOD ADD FOR ALL CONDITIONS       */
  /************************************************/
  // The method "Add" does addition on two BigBinary Integers a,b
  // Returns a+b, which is stored in another BigBinary Integer
  // calculatedResult ConvertToUsint converts bint
  // calculatedResult to integer

  bint calculatedResult;
  int expectedResult;
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    bint a("203450");
    bint b("2034");

    calculatedResult = a.Add(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing add_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    bint a("2034");
    bint b("203450");


    calculatedResult = a.Add(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing add_a_less_than_b";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
  // BYTE
  {
    bint a("768900");
    bint b("16523408");

    calculatedResult = a.Add(b);
    expectedResult = 17292308;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing overflow_to_next_byte";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
  // BYTE
  {
    bint a("35");
    bint b("1015");

    calculatedResult = a.Add(b);
    expectedResult = 1050;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing add_no_overflow_to_next_byte";
  }

  /************************************************/
  /* TESTING OPERATOR += FOR ALL CONDITIONS       */
  /************************************************/

  // The operator "+=(Add Equals)" does addition of two BigBinary
  // Integers a,b Calculates a+b, and stores result in a ConvertToUsint
  // converts bint a to integer


  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    bint a("2034");
    bint b("203");

    a+=b;
    expectedResult = 2237;

    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << " Failure testing add_equals_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    bint a("2034");
    bint b("203450");

    a+=b;
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Falure testing add_equals_a_less_than_b";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
  // BYTE
  {
    bint a("768900");
    bint b("16523408");

    a+=b;
    expectedResult = 17292308;

    EXPECT_EQ(expectedResult,a.ConvertToUsint())
      << "Falure testing add_equals_overflow_to_next_byte";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
  // BYTE
  {
    bint a("35");
    bint b("1015");

    a+=b;
    expectedResult = 1050;

    EXPECT_EQ(expectedResult,a.ConvertToUsint())
      << "Falure testing add_equals_no_overflow_to_next_byte";
  }
  /************************************************/
  /* TESTING METHOD SUB FOR ALL CONDITIONS      */
  /************************************************/

  // The method "Sub" does subtraction on two BigBinary Integers a,b
  // Returns a-b, which is stored in another BigBinary Integer
  // calculatedResult When a<b, the result is 0, since there is no
  // support for negative numbers as of now ConvertToUsint converts
  // bint calculatedResult to integer

  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

    bint a("20489");
    bint b("2034455");

    calculatedResult = a.Sub(b);
    expectedResult = 0;

    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing sub_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    bint a("2048956567");
    bint b("2048956567");

    calculatedResult = a.Sub(b);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing sub_a_equal_to_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    bint a("2048956567");
    bint b("2034455");

    calculatedResult = a.Sub(b);
    expectedResult = 2046922112;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing sub_a_greater_than_b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    bint a("196737");
    bint b("65406");

    calculatedResult = a.Sub(b);
    expectedResult = 131331;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing sub_borrow_from_next_byte";
  }

  /************************************************/
  /* TESTING OPERATOR -= FOR ALL CONDITIONS       */
  /************************************************/

  // The operator "-=(Sub Equals)" does subtractionn of two BigBinary
  // Integers a,b Calculates a-b, and stores result in a Results to 0,
  // when a<b, since there is no concept of negative number as of now
  // ConvertToUsint converts bint a to integer
  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

    bint a("20489");
    bint b("2034455");

    a-=b;
    expectedResult = 0;

    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //ZERO
    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing sub_equals_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    bint a("2048956567");
    bint b("2048956567");

    a-=b;
    expectedResult = 0;

    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing sub_equals_a_equal_to_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {

    bint a("2048956567");
    bint b("2034455");

    a-=b;
    expectedResult = 2046922112;

    EXPECT_EQ(expectedResult,a.ConvertToUsint())
      << "Failure testing sub_equals_a_greater_than_b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    bint a("196737");
    bint b("65406");

    a-=b;
    expectedResult = 131331;

    EXPECT_EQ(expectedResult,a.ConvertToUsint())
      << "Failure testing sub_equals_borrow_from_next_byte";
  }

  /************************************************/
  /* TESTING METHOD MUL FOR ALL CONDITIONS      */
  /************************************************/

  // The method "Mul" does multiplication on two BigBinary Integers
  // a,b Returns a*b, which is stored in another BigBinary Integer
  // calculatedResult ConvertToUsint converts bint
  // calculatedResult to integer
  {
    //ask about the branching if (b.m_MSB==0 or 1)
    bint a("1967");
    bint b("654");

    calculatedResult = a.Mul(b);
    expectedResult = 1286418;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing mul_test";
  }
  /************************************************/
  /* TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS */
  /************************************************/

  // The method "Divided By" does division of BigBinary Integer a by
  // another BigBinary Integer b Returns a/b, which is stored in another
  // BigBinary Integer calculatedResult ConvertToUsint converts
  // bint calculatedResult to integer When b=0, throws
  // error, since division by Zero is not allowed When a<b, returns 0,
  // since decimal value is not returned


  // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
  {
    bint a("2048");
    bint b("2034455");

    calculatedResult = a.DividedBy(b);
    expectedResult = 0;

    //RESULT SHOULD BE ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing divided_by_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {

    bint a("2048956567");
    bint b("2048956567");

    calculatedResult = a.DividedBy(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing divided_by_a_equals_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    bint a("2048956567");
    bint b("2034455");

    calculatedResult = a.DividedBy(b);
    expectedResult = 1007;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing divided_by_a_greater_than_b";
  }

}
TEST(UTbint,basic_compare){

  /************************************************/
  /* TESTING BASIC COMPARATOR METHODS AND OPERATORS */
  /**************************************************/

  /************************************************/
  /* TESTING METHOD COMPARE FOR ALL CONDITIONS    */
  /************************************************/

  // The method "Comapare" comapres two BigBinary Integers a,b
  // Returns:
  //    1, when a>b
  //    0, when a=b
  //   -1, when a<b
  //
  // Result is stored in signed integer, and then the result is
  // typecasted to int as EXPECT_EQ takes integer

  sint c;
  int expectedResult;

  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER
  {
    bint a("112504");
    bint b("46968");

    c = a.Compare(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
  {
    bint a("12504");
    bint b("46968");

    c = a.Compare(b);
    expectedResult = -1;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
  {
    bint a("34512504");
    bint b("34512504");

    c = a.Compare(b);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_equals_b";
  }
}

TEST(UTbint,mod_operations){

  /************************************************/
  /* TESTING METHOD MOD FOR ALL CONDITIONS        */
  /************************************************/

  // The method "Mod" does modulus operation on two BigBinary Integers
  // m,p Returns (m mod p), which is stored in another BigBinary Integer
  // calculatedResult ConvertToUsint converts bint r to
  // integer

  bint calculatedResult;
  int expectedResult;
  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD
  {
    bint m("27");
    bint p("240");

    calculatedResult = m.Mod(p);
    expectedResult = 27;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing number_less_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    bint m("93409673");
    bint p("406");

    calculatedResult = m.Mod(p);
    expectedResult = 35;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing number_greater_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
  {
    bint m("32768");
    bint p("16");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing number_dividible_by_modulus";
  }

  // TEST CASE WHEN THE NUMBER IS EQUAL TO MOD
  {
    bint m("67108913");
    bint p("67108913");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing number_equal_to_modulus";
  }


  /************************************************/
  /* TESTING METHOD MOD BARRETT FOR ALL CONDITIONS */
  /************************************************/


  /* 	The method "Divided By" does division of BigBinary Integer m by another BigBinary Integer p
	Function takes b as argument and operates on a
  	Returns a/b, which is stored in another BigBinary Integer calculatedResult
	ConvertToUsint converts bint calculatedResult to integer
	When b=0, throws error, since division by Zero is not allowed
	When a<b, returns 0, since decimal value is not returned
  */



  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

  /*TEST(UTbint_METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

    bint a("9587");
    bint b("3591");
    bint c("177");

    bint calculatedResult = a.ModBarrett(b,c);
    int expectedResult = 205484;

    std::cout<<"\n"<<d.ConvertToUsint()<<"\n";	//for testing purpose

    //EXPECT_EQ(27,calculatedResult.ConvertToUsint());
    }
  */

  /*************************************************/
  /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
  /*************************************************/
  // The method "Mod Inverse" operates on BigBinary Integers m,p
  // Returns {(m)^(-1)}mod p
  //    which is multiplicative inverse of m with respect to p, and is
  //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
  //    of m and p is 1)
  // If m and p are not co-prime, the method throws an error
  // ConvertToUsint converts bint calculatedResult to integer


  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    bint m("5");
    bint p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 65;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing number_less_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
  {
    bint m("3017");
    bint p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 77;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing number_greater_than_modulus";
  }


  /************************************************/
  /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
  /************************************************/
  // The method "Mod Add" operates on BigBinary Integers m,n,q
  //   Returns:
  //     (m+n)mod q
  //      = {(m mod q) + (n mod q)}mod q
  //   ConvertToUsint converts bint calculatedResult to integer




  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    bint m("58059595");
    bint n("3768");
    bint q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2871;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing first_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
  {
    bint m("595");
    bint n("376988");
    bint q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 3419;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing second_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
  {
    bint m("595");
    bint n("376");
    bint q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 971;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing both_numbers_less_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
  {

    bint m("59509095449");
    bint n("37654969960");
    bint q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2861;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing both_numbers_greater_than_modulus";
  }

  /************************************************/
  /* TESTING METHOD MODSUB FOR ALL CONDITIONS -*/
  /************************************************/

  // The method "Mod Sub" operates on BigBinary Integers m,n,q
  //   Returns:
  //    (m-n)mod q
  //    = {(m mod q) - (n mod q)}mod q	when m>n
  //    = 0 when m=n
  //    = {(m mod q)+q-(n mod q)}mod q when m<n

  //   ConvertToUsint converts bint calculatedResult to
  //   integer

  //MEMORY ALLOCATION ERROR IN MODSUB METHOD (due to copying value to null pointer)


  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    bint m("595");
    bint n("399");
    bint q("406");

    //std::cout << "Before : " << std::endl;

    calculatedResult = m.ModSub(n,q);
    expectedResult = 196;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing first_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
  {
    bint m("39960");
    bint n("595090959");
    bint q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 33029;

    //[{(a mod c)+ c} - (b mod c)] since a < b
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUsint())
      << "Failure testing first_number_less_than_modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
  {
    bint m("595090959");
    bint n("595090959");
    bint q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing first_number_equals_second_number";
  }

  /************************************************/
  /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Mul" operates on BigBinary Integers m,n,q
  //   Returns:  (m*n)mod q
  //              = {(m mod q)*(n mod q)}
  // ConvertToUsint converts bint calculatedResult to integer

  {
    bint m("39960");
    bint n("7959");
    bint q("406756");

    bint calculatedResult = m.ModMul(n,q);
    int expectedResult = 365204;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing mod_mul_test";
  }

  /************************************************/
  /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Exp" operates on BigBinary Integers m,n,q
  // Returns:  (m^n)mod q
  //   = {(m mod q)^(n mod q)}mod q
  // ConvertToUsint converts bint calculatedResult to integer

  {
    bint m("39960");
    bint n("9");
    bint q("406756");

    bint calculatedResult = m.ModExp(n,q);
    int expectedResult = 96776;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing mod_exp_test";
  }
}

TEST(UTbint,shift){

  /****************************/
  /* TESTING SHIFT OPERATORS  */
  /****************************/

  /*******************************************************/
  /* TESTING OPERATOR LEFT SHIFT (<<) FOR ALL CONDITIONS */
  /*******************************************************/

  // The operator 'Left Shift' operates on BigBinary Integer a, and it
  // is shifted by a number

  // Returns: a<<(num), and the result is stored in BigBinaryInterger
  // calculatedResult 'a' is left shifted by 'num' number of bits, and
  // filled up by 0s from right which is equivalent to a * (2^num)
  //
  //        example:
  //            4<<3 => (100)<<3 => (100000) => 32
  //           this is equivalent to: 4* (2^3) => 4*8 =32
  //ConvertToUsint converts bint calculatedResult to integer

  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    bint a("39960");
    usshort shift = 3;

    bint calculatedResult = a<<(shift);
    int expectedResult = 319680;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    bint a("39960");
    usshort shift = 6;

    bint calculatedResult = a<<(shift);
    int expectedResult = 2557440;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing shift_greater_than_max_shift";
  }


  /************************************************/
  /* TESTING OPERATOR LEFT SHIFT EQUALS (<<=) FOR ALL CONDITIONS -*/
  /************************************************/

  // The operator 'Left Shift Equals' operates on BigBinary Integer a,
  // and it is shifted by a number
  // Returns:
  // a<<(num), and the result is stored in 'a'
  // 'a' is left shifted by 'num' number of bits, and filled up by 0s
  // from right which is equivalent to a * (2^num)
  // example :4<<3 => (100)<<3 => (100000) => 32
  // this is equivalent to: 4* (2^3) => 4*8 =32
  // ConvertToUsint converts bint a to integer




  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    bint a("39960");
    usshort num = 3;

    a<<=(num);
    int expectedResult = 319680;

    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    bint a("39960");
    usshort num = 6;

    a<<=(num);
    int expectedResult = 2557440;

    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing shift_greater_than_max_shift";
  }


  /********************************************************/
  /* TESTING OPERATOR RIGHT SHIFT (>>) FOR ALL CONDITIONS */
  /********************************************************/
  // The operator 'Right Shift' operates on BigBinary Integer a, and it
  // is shifted by a number

  // Returns: a>>(num), and the result is stored in BigBinary Integer
  // calculated. Result 'a' is right shifted by 'num' number of bits,
  // and filled up by 0s from left which is equivalent to a / (2^num)

  //  ex:4>>3 => (100000)>>3 => (000100) => 4

  // this is equivalent to: 32*(2^3) => 32/8 = 4
  // ConvertToUsint converts bint calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    bint a("39965675");
    usshort shift = 3;

    bint calculatedResult = a>>(shift);
    int expectedResult = 4995709;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    bint a("39965675");
    usshort shift = 6;

    bint calculatedResult = a>>(shift);
    int expectedResult = 624463;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing shift_greater_than_max_shift";
  }


  /***************************************************************/
  /* TESTING OPERATOR RIGHT SHIFT EQUALS(>>=) FOR ALL CONDITIONS */
  /***************************************************************/

  // The operator 'Right Shift Equals' operates on BigBinary Integer a,
  // and it is shifted by a number

  // Returns: a>>=(num), and the result is stored in a 'a' is right
  // shifted by 'num' number of bits, and filled up by 0s from left
  // which is equivalent to a / (2^num)

  //   ex:4>>3 => (100000)>>3 => (000100) => 4

  //   this is equivalent to: 32*(2^3) => 32/8 = 4
  //   ConvertToUsint converts bint calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    bint a("39965675");
    usshort shift = 3;

    a>>=(shift);
    int expectedResult = 4995709;

    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    bint a("39965675");
    usshort shift = 6;

    a>>=(shift);
    int expectedResult = 624463;

    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing shift_greater_than_max_shift";
  }
}

/****************************************/
/* TESTING METHOD  BinaryToBigBinaryInt */
/****************************************/

TEST(UTbint,method_binary_string_to_bint){
  //TEST CASE FOR STATIC METHOD 

 std:string binaryString = "1011101101110001111010111011000000011";
  bint b =
    lbcrypto::bint::BinaryStringToBint(binaryString);

  bint expectedResult("100633769475");
  EXPECT_EQ(expectedResult, b)
    << "Failure testing BinaryToBigBinaryInt";
}

/****************************************/
/* TESTING METHOD  EXP                  */
/****************************************/
TEST(UTbint,method_exponentiation_without_modulus){

  bint x("56");
  bint result = x.Exp(10);

  bint expectedResult("303305489096114176");
  EXPECT_EQ(expectedResult, result)
    << "Failure testing exp";
}

TEST(UTbint, ConvertToDouble) {
  bint x("104037585658683683");
  double xInDouble = 104037585658683683;

  EXPECT_EQ(xInDouble, x.ConvertToDouble());
}
