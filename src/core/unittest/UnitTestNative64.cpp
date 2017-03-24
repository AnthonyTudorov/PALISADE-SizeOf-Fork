/*
  PRE SCHEME PROJECT, Crypto Lab, NJIT
  Version:
  v00.01
  Last Edited:
  11/15/2015
  List of Authors:
  TPOC:
  Dr. Kurt Rohloff, rohloff@njit.edu
  Programmers:
  Dr. Yuriy Polyakov, polyakov@njit.edu
  Gyana Sahu, grs22@njit.edu
  Nishanth Pasham, np386@njit.edu
  Dr. David Bruce Cousins, dcousins@bbn.com
  Description:
  This code exercises the math libraries of the PALISADE lattice encryption library.

  License Information:

  Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
  All rights reserved.
  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;


class UnitTestBinInt : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/************************************************/
/*	TESTING METHODS OF BININT CLASS		*/
/************************************************/

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/
TEST(UTNative64Int,basic_math){

  /************************************************/
  /* TESTING METHOD PLUS FOR ALL CONDITIONS       */
  /************************************************/
  // The method "Plus" does addition on two BigBinary Integers a,b
  // Returns a+b, which is stored in another BigBinary Integer
  // calculatedResult ConvertToInt converts native64::BigBinaryInteger
  // calculatedResult to integer

  native64::BigBinaryInteger calculatedResult;
  int expectedResult;
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    native64::BigBinaryInteger a("203450");
    native64::BigBinaryInteger b("2034");

    calculatedResult = a.Plus(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing plus_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    native64::BigBinaryInteger a("2034");
    native64::BigBinaryInteger b("203450");


    calculatedResult = a.Plus(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing plus_a_less_than_b";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
  // BYTE
  {
    native64::BigBinaryInteger a("768900");
    native64::BigBinaryInteger b("16523408");

    calculatedResult = a.Plus(b);
    expectedResult = 17292308;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing overflow_to_next_byte";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
  // BYTE
  {
    native64::BigBinaryInteger a("35");
    native64::BigBinaryInteger b("1015");

    calculatedResult = a.Plus(b);
    expectedResult = 1050;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing plus_no_overflow_to_next_byte";
  }

  /************************************************/
  /* TESTING OPERATOR += FOR ALL CONDITIONS       */
  /************************************************/

  // The operator "+=(Plus Equals)" does addition of two BigBinary
  // Integers a,b Calculates a+b, and stores result in a ConvertToInt
  // converts native64::BigBinaryInteger a to integer


  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    native64::BigBinaryInteger a("2034");
    native64::BigBinaryInteger b("203");

    a+=b;
    expectedResult = 2237;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << " Failure testing plus_equals_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    native64::BigBinaryInteger a("2034");
    native64::BigBinaryInteger b("203450");

    a+=b;
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Falure testing plus_equals_a_less_than_b";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
  // BYTE
  {
    native64::BigBinaryInteger a("768900");
    native64::BigBinaryInteger b("16523408");

    a+=b;
    expectedResult = 17292308;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Falure testing plus_equals_overflow_to_next_byte";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
  // BYTE
  {
    native64::BigBinaryInteger a("35");
    native64::BigBinaryInteger b("1015");

    a+=b;
    expectedResult = 1050;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Falure testing plus_equals_no_overflow_to_next_byte";
  }
  /************************************************/
  /* TESTING METHOD MINUS FOR ALL CONDITIONS      */
  /************************************************/

  // The method "Minus" does subtraction on two BigBinary Integers a,b
  // Returns a-b, which is stored in another BigBinary Integer
  // calculatedResult When a<b, the result is 0, since there is no
  // support for negative numbers as of now ConvertToInt converts
  // native64::BigBinaryInteger calculatedResult to integer

  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

    native64::BigBinaryInteger a("20489");
    native64::BigBinaryInteger b("2034455");

    calculatedResult = a.Minus(b);
    expectedResult = 0;

    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing minus_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    native64::BigBinaryInteger a("2048956567");
    native64::BigBinaryInteger b("2048956567");

    calculatedResult = a.Minus(b);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing minus_a_equal_to_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    native64::BigBinaryInteger a("2048956567");
    native64::BigBinaryInteger b("2034455");

    calculatedResult = a.Minus(b);
    expectedResult = 2046922112;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing minus_a_greater_than_b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    native64::BigBinaryInteger a("196737");
    native64::BigBinaryInteger b("65406");

    calculatedResult = a.Minus(b);
    expectedResult = 131331;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing minus_borrow_from_next_byte";
  }

  /************************************************/
  /* TESTING OPERATOR -= FOR ALL CONDITIONS       */
  /************************************************/

  // The operator "-=(Minus Equals)" does subtractionn of two BigBinary
  // Integers a,b Calculates a-b, and stores result in a Results to 0,
  // when a<b, since there is no concept of negative number as of now
  // ConvertToInt converts native64::BigBinaryInteger a to integer
  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

    native64::BigBinaryInteger a("20489");
    native64::BigBinaryInteger b("2034455");

    a-=b;
    expectedResult = 0;

    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //ZERO
    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing minus_equals_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    native64::BigBinaryInteger a("2048956567");
    native64::BigBinaryInteger b("2048956567");

    a-=b;
    expectedResult = 0;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing minus_equals_a_equal_to_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {

    native64::BigBinaryInteger a("2048956567");
    native64::BigBinaryInteger b("2034455");

    a-=b;
    expectedResult = 2046922112;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Failure testing minus_equals_a_greater_than_b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    native64::BigBinaryInteger a("196737");
    native64::BigBinaryInteger b("65406");

    a-=b;
    expectedResult = 131331;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Failure testing minus_equals_borrow_from_next_byte";
  }

  /************************************************/
  /* TESTING METHOD TIMES FOR ALL CONDITIONS      */
  /************************************************/

  // The method "Times" does multiplication on two BigBinary Integers
  // a,b Returns a*b, which is stored in another BigBinary Integer
  // calculatedResult ConvertToInt converts native64::BigBinaryInteger
  // calculatedResult to integer
  {
    //ask about the branching if (b.m_MSB==0 or 1)
    native64::BigBinaryInteger a("1967");
    native64::BigBinaryInteger b("654");

    calculatedResult = a.Times(b);
    expectedResult = 1286418;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing times_test";
  }
  /************************************************/
  /* TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS */
  /************************************************/

  // The method "Divided By" does division of BigBinary Integer a by
  // another BigBinary Integer b Returns a/b, which is stored in another
  // BigBinary Integer calculatedResult ConvertToInt converts
  // native64::BigBinaryInteger calculatedResult to integer When b=0, throws
  // error, since division by Zero is not allowed When a<b, returns 0,
  // since decimal value is not returned


  // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
  {
    native64::BigBinaryInteger a("2048");
    native64::BigBinaryInteger b("2034455");

    calculatedResult = a.DividedBy(b);
    expectedResult = 0;

    //RESULT SHOULD BE ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {

    native64::BigBinaryInteger a("2048956567");
    native64::BigBinaryInteger b("2048956567");

    calculatedResult = a.DividedBy(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_equals_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    native64::BigBinaryInteger a("2048956567");
    native64::BigBinaryInteger b("2034455");

    calculatedResult = a.DividedBy(b);
    expectedResult = 1007;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_greater_than_b";
  }


  {
	  native64::BigBinaryInteger a("8096");
	  native64::BigBinaryInteger b("4049");

	  calculatedResult = a.Mod(b);
	  expectedResult = 4047;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing Mod";
  }

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.

  {
	  native64::BigBinaryInteger a("8096");
	  native64::BigBinaryInteger b("4049");

	  calculatedResult = a.DivideAndRound(b);
	  expectedResult = 2;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }

  /*{
    native64::BigBinaryInteger a("204");
    native64::BigBinaryInteger b("210");

    calculatedResult = a.DivideAndRound(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.
  {
	  native64::BigBinaryInteger a("100");
	  native64::BigBinaryInteger b("210");

	  calculatedResult = a.DivideAndRound(b);
	  expectedResult = 0;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }*/

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.
  /*{
    native64::BigBinaryInteger a("4048");
    native64::BigBinaryInteger b("4049");
    native64::BigBinaryInteger c("2");

    calculatedResult = a.MultiplyAndRound(c, b);
    expectedResult = 2;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }*/
}

TEST(UTNative64Int,basic_compare){

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
    native64::BigBinaryInteger a("112504");
    native64::BigBinaryInteger b("46968");

    c = a.Compare(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
  {
    native64::BigBinaryInteger a("12504");
    native64::BigBinaryInteger b("46968");

    c = a.Compare(b);
    expectedResult = -1;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
  {
    native64::BigBinaryInteger a("34512504");
    native64::BigBinaryInteger b("34512504");

    c = a.Compare(b);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_equals_b";
  }
}

TEST(UTNative64Int,mod_operations){

  /************************************************/
  /* TESTING METHOD MOD FOR ALL CONDITIONS        */
  /************************************************/

  // The method "Mod" does modulus operation on two BigBinary Integers
  // m,p Returns (m mod p), which is stored in another BigBinary Integer
  // calculatedResult ConvertToInt converts native64::BigBinaryInteger r to
  // integer

  native64::BigBinaryInteger calculatedResult;
  int expectedResult;
  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD
  {
    native64::BigBinaryInteger m("27");
    native64::BigBinaryInteger p("240");

    calculatedResult = m.Mod(p);
    expectedResult = 27;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_less_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    native64::BigBinaryInteger m("93409673");
    native64::BigBinaryInteger p("406");

    calculatedResult = m.Mod(p);
    expectedResult = 35;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_greater_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
  {
    native64::BigBinaryInteger m("32768");
    native64::BigBinaryInteger p("16");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_dividible_by_modulus";
  }

  // TEST CASE WHEN THE NUMBER IS EQUAL TO MOD
  {
    native64::BigBinaryInteger m("67108913");
    native64::BigBinaryInteger p("67108913");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_equal_to_modulus";
  }
}

  /************************************************/
  /* TESTING METHOD MOD BARRETT FOR ALL CONDITIONS */
  /************************************************/


  /* 	The method "Divided By" does division of BigBinary Integer m by another BigBinary Integer p
	Function takes b as argument and operates on a
  	Returns a/b, which is stored in another BigBinary Integer calculatedResult
	ConvertToInt converts native64::BigBinaryInteger calculatedResult to integer
	When b=0, throws error, since division by Zero is not allowed
	When a<b, returns 0, since decimal value is not returned
  */



  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

  /*TEST(UTNative64Int_METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

    native64::BigBinaryInteger a("9587");
    native64::BigBinaryInteger b("3591");
    native64::BigBinaryInteger c("177");

    native64::BigBinaryInteger calculatedResult = a.ModBarrett(b,c);
    int expectedResult = 205484;

    std::cout<<"\n"<<d.ConvertToInt()<<"\n";	//for testing purpose

    //EXPECT_EQ(27,calculatedResult.ConvertToInt());
    }
  */
TEST(UTNative64Int,mod_inverse){
  /*************************************************/
  /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
  /*************************************************/
  // The method "Mod Inverse" operates on BigBinary Integers m,p
  // Returns {(m)^(-1)}mod p
  //    which is multiplicative inverse of m with respect to p, and is
  //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
  //    of m and p is 1)
  // If m and p are not co-prime, the method throws an error
  // ConvertToInt converts native64::BigBinaryInteger calculatedResult to integer

  native64::BigBinaryInteger calculatedResult;
  int expectedResult;

  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    native64::BigBinaryInteger m("5");
    native64::BigBinaryInteger p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 65;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_less_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
  {
    native64::BigBinaryInteger m("3017");
    native64::BigBinaryInteger p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 77;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_greater_than_modulus";
  }

  //TESTCASE

  //testcase that failed during testing.
  {

    native64::BigBinaryInteger first("4974113608263");
    native64::BigBinaryInteger second("486376675628");
    string modcorrect("110346851983");
    native64::BigBinaryInteger modresult;

    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult.ToString())
      <<"Failure ModInverse() Mod regression test";


    native64::BigBinaryInteger input ("405107564542978792");
    native64::BigBinaryInteger modulus("1152921504606847009");
    string modIcorrect("844019068664266609");
    native64::BigBinaryInteger modIresult;

    bool thrown = false;
    try {
      modIresult = input.ModInverse(modulus);
    }
    catch (...){
      thrown = true;
    }

    EXPECT_FALSE(thrown)
      << "Failure testing ModInverse() non co-prime arguments";
    EXPECT_EQ(modIcorrect, modIresult.ToString())
      <<"Failure ModInverse() regression test";
  }



  // Mod(0)
  {
#if 0 //BBI just hangs, do not run this test.
    native64::BigBinaryInteger first("4974113608263");
    native64::BigBinaryInteger second("0");
    string modcorrect("4974113608263");
    native64::BigBinaryInteger modresult;

    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult.ToString())
      <<"Failure ModInverse() Mod(0)";
#endif
  }


}


TEST(UTNative64Int,mod_arithmetic){
  native64::BigBinaryInteger calculatedResult;
  uint64_t expectedResult;
  /************************************************/
  /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
  /************************************************/
  // The method "Mod Add" operates on BigBinary Integers m,n,q
  //   Returns:
  //     (m+n)mod q
  //      = {(m mod q) + (n mod q)}mod q
  //   ConvertToInt converts native64::BigBinaryInteger calculatedResult to integer




  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    native64::BigBinaryInteger m("58059595");
    native64::BigBinaryInteger n("3768");
    native64::BigBinaryInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2871;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing first_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
  {
    native64::BigBinaryInteger m("595");
    native64::BigBinaryInteger n("376988");
    native64::BigBinaryInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 3419;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing second_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
  {
    native64::BigBinaryInteger m("595");
    native64::BigBinaryInteger n("376");
    native64::BigBinaryInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 971;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing both_numbers_less_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
  {

    native64::BigBinaryInteger m("59509095449");
    native64::BigBinaryInteger n("37654969960");
    native64::BigBinaryInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2861;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing both_numbers_greater_than_modulus";
  }

  {
	native64::BigBinaryInteger m( "4611686019217177693" );
	native64::BigBinaryInteger n( "2305843009213700738" );
	native64::BigBinaryInteger q( "4611686019217177861" );

	calculatedResult = m.ModAdd(n,q);
	expectedResult = 2305843009213700570;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing really big numbers";
  }

  {
	native64::BigBinaryInteger m( "13835058055282163712" );
	native64::BigBinaryInteger n( "13835058055282163719" );
	native64::BigBinaryInteger q( "13835058055282163729" );

	calculatedResult = m.ModAdd(n,q);
	expectedResult = 13835058055282163702;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic); this test is expected to fail in Visual Studio";
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

  //   ConvertToInt converts native64::BigBinaryInteger calculatedResult to
  //   integer

  //MEMORY ALLOCATION ERROR IN MODSUB METHOD (due to copying value to null pointer)


  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    native64::BigBinaryInteger m("595");
    native64::BigBinaryInteger n("399");
    native64::BigBinaryInteger q("406");

    //std::cout << "Before : " << std::endl;

    calculatedResult = m.ModSub(n,q);
    expectedResult = 196;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing first_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
  {
    native64::BigBinaryInteger m("39960");
    native64::BigBinaryInteger n("595090959");
    native64::BigBinaryInteger q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 33029;

    //[{(a mod c)+ c} - (b mod c)] since a < b
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing first_number_less_than_modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
  {
    native64::BigBinaryInteger m("595090959");
    native64::BigBinaryInteger n("595090959");
    native64::BigBinaryInteger q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing first_number_equals_second_number";
  }

  /************************************************/
  /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Mul" operates on BigBinary Integers m,n,q
  //   Returns:  (m*n)mod q
  //              = {(m mod q)*(n mod q)}
  // ConvertToInt converts native64::BigBinaryInteger calculatedResult to integer

  {
    native64::BigBinaryInteger m("39960");
    native64::BigBinaryInteger n("7959");
    native64::BigBinaryInteger q("406756");

    native64::BigBinaryInteger calculatedResult = m.ModMul(n,q);
    int expectedResult = 365204;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing mod_mul_test";
  }

  /************************************************/
  /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Exp" operates on BigBinary Integers m,n,q
  // Returns:  (m^n)mod q
  //   = {(m mod q)^(n mod q)}mod q
  // ConvertToInt converts native64::BigBinaryInteger calculatedResult to integer

  {
    native64::BigBinaryInteger m("39960");
    native64::BigBinaryInteger n("9");
    native64::BigBinaryInteger q("406756");

    native64::BigBinaryInteger calculatedResult = m.ModExp(n,q);
    int expectedResult = 96776;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing mod_exp_test";
  }

  {
	native64::BigBinaryInteger m( "4611686019217177693" );
	native64::BigBinaryInteger n( "2305843009213700738" );
	native64::BigBinaryInteger q( "4611686019217177861" );

	calculatedResult = m.ModMul(n,q);
	expectedResult = 66341216340;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic);  this test is expected to fail in Visual Studio";
  }

  {
	native64::BigBinaryInteger m( "13835058055282163712" );
	native64::BigBinaryInteger n( "13835058055282163719" );
	native64::BigBinaryInteger q( "13835058055282163729" );

	calculatedResult = m.ModMul(n,q);
	expectedResult = 170;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic);  this test is expected to fail in Visual Studio";
  }
}

TEST(UTNative64Int,shift){

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
  //ConvertToInt converts native64::BigBinaryInteger calculatedResult to integer

  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    native64::BigBinaryInteger a("39960");
    usshort shift = 3;

    native64::BigBinaryInteger calculatedResult = a<<(shift);
    int expectedResult = 319680;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    native64::BigBinaryInteger a("39960");
    usshort shift = 6;

    native64::BigBinaryInteger calculatedResult = a<<(shift);
    int expectedResult = 2557440;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
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
  // ConvertToInt converts native64::BigBinaryInteger a to integer




  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    native64::BigBinaryInteger a("39960");
    usshort num = 3;

    a<<=(num);
    int expectedResult = 319680;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    native64::BigBinaryInteger a("39960");
    usshort num = 6;

    a<<=(num);
    int expectedResult = 2557440;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
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
  // ConvertToInt converts native64::BigBinaryInteger calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    native64::BigBinaryInteger a("39965675");
    usshort shift = 3;

    native64::BigBinaryInteger calculatedResult = a>>(shift);
    int expectedResult = 4995709;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    native64::BigBinaryInteger a("39965675");
    usshort shift = 6;

    native64::BigBinaryInteger calculatedResult = a>>(shift);
    int expectedResult = 624463;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
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
  //   ConvertToInt converts native64::BigBinaryInteger calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    native64::BigBinaryInteger a("39965675");
    usshort shift = 3;

    a>>=(shift);
    int expectedResult = 4995709;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    native64::BigBinaryInteger a("39965675");
    usshort shift = 6;

    a>>=(shift);
    int expectedResult = 624463;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_greater_than_max_shift";
  }
}

/****************************************/
/* TESTING METHOD  BinaryStringToBigBinaryInt */
/****************************************/

TEST(UTNative64Int,method_binary_string_to_big_binary_integer){
  //TEST CASE FOR STATIC METHOD BinaryStringToBigBinaryInt in native64::BigBinaryInteger

 std:string binaryString = "1011101101110001111010111011000000011";
  native64::BigBinaryInteger b =
    native64::BigBinaryInteger::BinaryStringToBigBinaryInt(binaryString);

  native64::BigBinaryInteger expectedResult("100633769475");
  EXPECT_EQ(expectedResult, b)
    << "Failure testing BinaryStringToBigBinaryInt";
}

/****************************************/
/* TESTING METHOD  EXP                  */
/****************************************/
TEST(UTNative64Int,method_exponentiation_without_modulus){

  native64::BigBinaryInteger x("56");
  native64::BigBinaryInteger result = x.Exp(10);

  native64::BigBinaryInteger expectedResult("303305489096114176");
  EXPECT_EQ(expectedResult, result)
    << "Failure testing exp";
}

TEST(UTNative64Int,method_ConvertToDouble) {
  native64::BigBinaryInteger x("104037585658683683");
  double xInDouble = 104037585658683683;

  EXPECT_EQ(xInDouble, x.ConvertToDouble());
}