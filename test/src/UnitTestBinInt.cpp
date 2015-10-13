/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	9/29/2015 4:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
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

#include "gtest/gtest.h"
#include <iostream>

#include "../../src/math/backend.h"
#include "../../src/utils/inttypes.h"
#include "../../src/math/nbtheory.h"
#include "../../src/lattice/ideals.h"
#include "../../src/math/distrgen.h"
#include "../../src/crypto/lwecrypt.h"
#include "../../src/crypto/lwepre.h"
#include "../../src/lattice/il2n.h"
#include "../../src/utils/utilities.h"

/*
#include "binint.h"
#include "binmat.h"
#include "binvect.h"
#include "inttypes.h"
#include "nbtheory.h"
#include "ideals.h"
#include "distrgen.h"
#include "lwecrypt.h"
#include "lwepre.h"
#include "il2n.h"
#include "utilities.h"
*/

using namespace std;
using namespace lbcrypto;

/*
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
*/
class UnitTestBinInt : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/*
EXPECT_EQ (expected, actual) verifies expected == actual.
Compares two integer values
*/


/*---------------------------------------	TESTING METHODS OF BININT CLASS		--------------------------------------------*/



/*--------------TESTING METHOD PLUS FOR ALL CONDITIONS---------------------------*/

/* 	   The method "Plus" does addition on two BigBinary Integers a,b
  	   Returns a+b, which is stored in another BigBinary Integer calculatedResult
	   ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/

// TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB HAS NO OVERFLOW

TEST(method_plus,plus_a_greater_than_b){

	BigBinaryInteger a("203450");
	BigBinaryInteger b("2034");

	BigBinaryInteger calculatedResult = a.Plus(b);
	int expectedResult = 205484;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}


// TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB HAS NO OVERFLOW

TEST(method_plus,plus_a_less_than_b){

	BigBinaryInteger a("2034");	
	BigBinaryInteger b("203450");

	BigBinaryInteger calculatedResult = a.Plus(b);
	int expectedResult = 205484;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}


// TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT BYTE

TEST(method_plus,plus_overflow_to_next_byte){

	BigBinaryInteger a("768900");
	BigBinaryInteger b("16523408");	

	BigBinaryInteger calculatedResult = a.Plus(b);
	int expectedResult = 17292308;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}


// TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME BYTE

TEST(method_plus,plus_no_overflow_to_next_byte){

	BigBinaryInteger a("35");	
	BigBinaryInteger b("1015");

	BigBinaryInteger calculatedResult = a.Plus(b);
	int expectedResult = 1050;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}



/*--------------TESTING OPERATOR += FOR ALL CONDITIONS---------------------------*/


/* 	   The operator "+=(Plus Equals)" does addition of two BigBinary Integers a,b
  	   Calculates a+b, and stores result in a
	   ConvertToInt converts BigBinaryInteger a to integer
*/


// TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB HAS NO OVERFLOW

TEST(operator_plus_equals,plus_equals_a_greater_than_b){

	BigBinaryInteger a("2034");
	BigBinaryInteger b("203");

	a+=b;
	int expectedResult = 2237;

	EXPECT_EQ(expectedResult, a.ConvertToInt());
}


// TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB HAS NO OVERFLOW

TEST(operator_plus_equals,plus_equals_a_less_than_b){

	BigBinaryInteger a("2034");	
	BigBinaryInteger b("203450");

	a+=b;
	int expectedResult = 205484;

	EXPECT_EQ(expectedResult, a.ConvertToInt());
}


// TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT BYTE

TEST(operator_plus_equals,plus_equals_overflow_to_next_byte){

	BigBinaryInteger a("768900");
	BigBinaryInteger b("16523408");	

	a+=b;
	int expectedResult = 17292308;

	EXPECT_EQ(expectedResult,a.ConvertToInt());
}


// TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME BYTE

TEST(operator_plus_equals,plus_equals_no_overflow_to_next_byte){

	BigBinaryInteger a("35");	
	BigBinaryInteger b("1015");

	a+=b;
	int expectedResult = 1050;

	EXPECT_EQ(expectedResult,a.ConvertToInt());
}




/*--------------TESTING METHOD MINUS FOR ALL CONDITIONS---------------------------*/


/* 	   The method "Minus" does subtraction on two BigBinary Integers a,b
  	   Returns a-b, which is stored in another BigBinary Integer calculatedResult
	   When a<b, the result is 0, since there is no support for negative numbers as of now
	   ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/


// TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

TEST(method_minus,minus_a_less_than_b){

	BigBinaryInteger a("20489");
	BigBinaryInteger b("2034455");

	BigBinaryInteger calculatedResult = a.Minus(b);
	int expectedResult = 0;

	//SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE ZERO
	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}


// TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER

TEST(method_minus,minus_a_equal_to_b){

	BigBinaryInteger a("2048956567");
	BigBinaryInteger b("2048956567");

	BigBinaryInteger calculatedResult = a.Minus(b);
	int expectedResult = 0;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}


// TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER

TEST(method_minus,minus_a_greater_than_b){

	BigBinaryInteger a("2048956567");
	BigBinaryInteger b("2034455");

	BigBinaryInteger calculatedResult = a.Minus(b);
	int expectedResult = 2046922112;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}


// TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE

TEST(method_minus,minus_borrow_from_next_byte){

	BigBinaryInteger a("196737");
	BigBinaryInteger b("65406");

	BigBinaryInteger calculatedResult = a.Minus(b);
	int expectedResult = 131331;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}



/*--------------TESTING OPERATOR -= FOR ALL CONDITIONS---------------------------*/


/* 	The operator "-=(Minus Equals)" does subtractionn of two BigBinary Integers a,b
	Calculates a-b, and stores result in a
	Results to 0, when a<b, since there is no concept of negative number as of now
	ConvertToInt converts BigBinaryInteger a to integer
*/

// TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

TEST(operator_minus_equals,minus_equals_a_less_than_b){

	BigBinaryInteger a("20489");
	BigBinaryInteger b("2034455");

	a-=b;
	int expectedResult = 0;

	//SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE ZERO
	EXPECT_EQ(expectedResult, a.ConvertToInt());
}


// TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER

TEST(operator_minus_equals,minus_equals_a_equal_to_b){

	BigBinaryInteger a("2048956567");
	BigBinaryInteger b("2048956567");

	a-=b;
	int expectedResult = 0;

	EXPECT_EQ(expectedResult, a.ConvertToInt());
}


// TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER

TEST(operator_minus_equals,minus_equals_a_greater_than_b){

	BigBinaryInteger a("2048956567");
	BigBinaryInteger b("2034455");

	a-=b;
	int expectedResult = 2046922112;

	EXPECT_EQ(expectedResult,a.ConvertToInt());
}


// TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE

TEST(operator_minus_equals,minus_equals_borrow_from_next_byte){

	BigBinaryInteger a("196737");
	BigBinaryInteger b("65406");

	a-=b;
	int expectedResult = 131331;

	EXPECT_EQ(expectedResult,a.ConvertToInt());
}



/*--------------TESTING METHOD TIMES FOR ALL CONDITIONS---------------------------*/

/* 	   The method "Times" does multiplication on two BigBinary Integers a,b
  	   Returns a*b, which is stored in another BigBinary Integer calculatedResult
	   ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/


TEST(method_times,times_test){
	//ask about the branching if (b.m_MSB==0 or 1)

	BigBinaryInteger a("1967");
	BigBinaryInteger b("654");

	BigBinaryInteger calculatedResult = a.Times(b);
	int expectedResult = 1286418;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}



/*--------------TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS---------------------------*/


// TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER


/* 	The method "Divided By" does division of BigBinary Integer a by another BigBinary Integer b
  	Returns a/b, which is stored in another BigBinary Integer calculatedResult
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
	When b=0, throws error, since division by Zero is not allowed
	When a<b, returns 0, since decimal value is not returned
*/


TEST(method_divided_by,divided_by_a_less_than_b){

	BigBinaryInteger a("2048");
	BigBinaryInteger b("2034455");

	BigBinaryInteger calculatedResult = a.DividedBy(b);
	int expectedResult = 0;

	//RESULT SHOULD BE ZERO
	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}


// TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER

TEST(method_divided_by,divided_by_a_equals_b){

	BigBinaryInteger a("2048956567");
	BigBinaryInteger b("2048956567");

	BigBinaryInteger calculatedResult = a.DividedBy(b);
	int expectedResult = 1;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}


// TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER

TEST(method_divided_by, divided_by_a_greater_than_b){

	BigBinaryInteger a("2048956567");
	BigBinaryInteger b("2034455");

	BigBinaryInteger calculatedResult = a.DividedBy(b);
	int expectedResult = 1007;
	
	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}



/*--------------TESTING METHOD COMPARE FOR ALL CONDITIONS---------------------------*/


/* 	The method "Comapare" comapres two BigBinary Integers a,b
  	Returns: 
		 1, when a>b
		 0, when a=b
		-1, when a<b

	Result is stored in signed integer, and then the result is typecasted to int as EXPECT_EQ takes integer
*/



// TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER

TEST(method_compare,compare_a_greater_than_b){

	BigBinaryInteger a("112504");
	BigBinaryInteger b("46968");

	sint c = a.Compare(b);
	int expectedResult = 1;

	EXPECT_EQ(expectedResult,(int)c);
}

// TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER

TEST(method_compare,compare_a_less_than_b){

	BigBinaryInteger a("12504");
	BigBinaryInteger b("46968");

	sint c = a.Compare(b);
	int expectedResult = -1;

	EXPECT_EQ(expectedResult,(int)c);
}
// TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER

TEST(method_compare,compare_a_equals_b){

	BigBinaryInteger a("34512504");
	BigBinaryInteger b("34512504");

	sint c = a.Compare(b);
	int expectedResult = 0;

	EXPECT_EQ(expectedResult,(int)c);
}



/*--------------TESTING METHOD MOD FOR ALL CONDITIONS---------------------------*/


/* 	The method "Mod" does modulus operation on two BigBinary Integers m,p
	Returns (m mod p), which is stored in another BigBinary Integer calculatedResult
	ConvertToInt converts BigBinaryInteger r to integer
*/


// TEST CASE WHEN THE NUMBER IS LESS THAN MOD

TEST(method_modulus,number_less_than_modulus){

	BigBinaryInteger m("27");
	BigBinaryInteger p("240");

	BigBinaryInteger calculatedResult = m.Mod(p);
	int expectedResult = 27;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}


// TEST CASE WHEN THE NUMBER IS GREATER THAN MOD

TEST(method_modulus,number_greater_than_modulus){

	BigBinaryInteger m("93409673");
	BigBinaryInteger p("406");

	BigBinaryInteger calculatedResult = m.Mod(p);
	int expectedResult = 35;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}


// TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD

TEST(method_modulus,number_dividible_by_modulus){

	BigBinaryInteger m("32768");
	BigBinaryInteger p("16");

	BigBinaryInteger calculatedResult = m.Mod(p);
	int expectedResult = 0;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}




/*--------------TESTING METHOD MOD BARRETT FOR ALL CONDITIONS---------------------------*/


/* 	The method "Divided By" does division of BigBinary Integer m by another BigBinary Integer p
	Function takes b as argument and operates on a
  	Returns a/b, which is stored in another BigBinary Integer calculatedResult
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
	When b=0, throws error, since division by Zero is not allowed
	When a<b, returns 0, since decimal value is not returned
*/



// TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

/*TEST(METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

	BigBinaryInteger a("9587");
	BigBinaryInteger b("3591");
	BigBinaryInteger c("177");

	BigBinaryInteger calculatedResult = a.ModBarrett(b,c);
	int expectedResult = 205484;

	std::cout<<"\n"<<d.ConvertToInt()<<"\n";	//for testing purpose

	//EXPECT_EQ(27,calculatedResult.ConvertToInt());
}
*/


/*--------------TESTING METHOD MOD INVERSE FOR ALL CONDITIONS---------------------------*/


/* 	The method "Mod Inverse" operates on BigBinary Integers m,p
  	Returns {(m)^(-1)}mod p
		which is multiplicative inverse of m with respect to p, 
		and is uses extended Euclidean algorithm
		m and p are co-primes (i,e GCD of m and p is 1)
	If m and p are not co-prime, the method throws an error
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/


// TEST CASE WHEN THE NUMBER IS GREATER THAN MOD

TEST(method_mod_inverse,number_less_than_modulus){

	BigBinaryInteger m("5");
	BigBinaryInteger p("108");

	BigBinaryInteger calculatedResult = m.ModInverse(p);
	int expectedResult = 65;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}

// TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME

TEST(method_mod_inverse,number_greater_than_modulus){

	BigBinaryInteger m("3017");
	BigBinaryInteger p("108");

	BigBinaryInteger calculatedResult = m.ModInverse(p);
	int expectedResult = 77;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}



/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Add" operates on BigBinary Integers m,n,q
  	Returns:
		 (m+n)mod q 
		 = {(m mod q) + (n mod q)}mod q
	
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/

// TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD

TEST(method_mod_add,first_number_greater_than_modulus){

	BigBinaryInteger m("58059595");
	BigBinaryInteger n("3768");
	BigBinaryInteger q("4067");

	BigBinaryInteger calculatedResult = m.ModAdd(n,q);
	int expectedResult = 2871;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}


// TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD

TEST(method_mod_add,second_number_greater_than_modulus){

	BigBinaryInteger m("595");
	BigBinaryInteger n("376988");
	BigBinaryInteger q("4067");

	BigBinaryInteger calculatedResult = m.ModAdd(n,q);
	int expectedResult = 3419;

	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}



// TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD

TEST(method_mod_add,both_numbers_less_than_modulus){

	BigBinaryInteger m("595");
	BigBinaryInteger n("376");
	BigBinaryInteger q("4067");

	BigBinaryInteger calculatedResult = m.ModAdd(n,q);
	int expectedResult = 971;

}



// TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD

TEST(method_mod_add,both_numbers_greater_than_modulus){

	BigBinaryInteger m("59509095449");
	BigBinaryInteger n("37654969960");
	BigBinaryInteger q("4067");

	BigBinaryInteger calculatedResult = m.ModAdd(n,q);
	int expectedResult = 2861;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}



/*--------------TESTING METHOD MODSUB FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Sub" operates on BigBinary Integers m,n,q
  	Returns:
		 (m-n)mod q 
		 = {(m mod q) - (n mod q)}mod q	when m>n
		 = 0 when m=n
		 = {(m mod q)+q-(n mod q)}mod q when m<n
	
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/


//MEMORY ALLOCATION ERROR IN MODSUB METHOD (due to copying value to null pointer)

// TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD

TEST(method_mod_sub, first_number_greater_than_modulus){

	BigBinaryInteger m("595");
	BigBinaryInteger n("399");
	BigBinaryInteger q("406");

	BigBinaryInteger calculatedResult = m.ModSub(n,q);
	int expectedResult = 196;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}



// TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD

TEST(method_mod_sub, first_number_less_than_modulus){

	BigBinaryInteger m("39960");
	BigBinaryInteger n("595090959");
	BigBinaryInteger q("406756");

	BigBinaryInteger calculatedResult = m.ModSub(n,q);
	int expectedResult = 33029;
	
	//[{(a mod c)+ c} - (b mod c)] since a < b
	EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt());
}


// TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER 

TEST(method_mod_sub, first_number_equals_second_number){

	BigBinaryInteger m("595090959");
	BigBinaryInteger n("595090959");
	BigBinaryInteger q("406756");

	BigBinaryInteger calculatedResult = m.ModSub(n,q);
	int expectedResult = 0;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}



/*--------------TESTING METHOD MODMUL FOR ALL CONDITIONS---------------------------*/


/* 	The method "Mod Mul" operates on BigBinary Integers m,n,q
  	Returns:  (m*n)mod q
		= {(m mod q)*(n mod q)} 
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/

TEST(method_mod_mul,mod_mul_test){

	BigBinaryInteger m("39960");
	BigBinaryInteger n("7959");
	BigBinaryInteger q("406756");

	BigBinaryInteger calculatedResult = m.ModMul(n,q);
	int expectedResult = 365204;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}



/*--------------TESTING METHOD MODEXP FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Exp" operates on BigBinary Integers m,n,q
  	Returns:  (m^n)mod q 
		= {(m mod q)^(n mod q)}mod q
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/

TEST(method_mod_exp,mod_exp_test){

	BigBinaryInteger m("39960");
	BigBinaryInteger n("9");
	BigBinaryInteger q("406756");

	BigBinaryInteger calculatedResult = m.ModExp(n,q);
	int expectedResult = 96776;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}




/*--------------TESTING OPERATOR LEFT SHIFT (<<) FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Left Shift" operates on BigBinary Integer a, and it is shifted by a number
  	Returns:  a<<(num), and the result is stored in BigBinaryInterger calculatedResult
		"a" is left shifted by "num" number of bits, and filled up by 0s from right
		which is equivalent to a * (2^num)

		ex:4<<3 => (100)<<3 => (100000) => 32
		this is equivalent to: 4* (2^3) => 4*8 =32 
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/

// TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)

TEST(method_left_shift,shift_less_than_max_shift){

	BigBinaryInteger a("39960");
	usshort shift = 3;

	BigBinaryInteger calculatedResult = a<<(shift);
	int expectedResult = 319680;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}



// TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)

TEST(method_left_shift,shift_greater_than_max_shift){

	BigBinaryInteger a("39960");
	usshort shift = 6;

	BigBinaryInteger calculatedResult = a<<(shift);
	int expectedResult = 2557440;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}


/*--------------TESTING OPERATOR LEFT SHIFT EQUALS (<<=) FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Left Shift Equals" operates on BigBinary Integer a, and it is shifted by a number
  	Returns:  a<<(num), and the result is stored in a
		"a" is left shifted by "num" number of bits, and filled up by 0s from right
		which is equivalent to a * (2^num)

		ex:4<<3 => (100)<<3 => (100000) => 32
		this is equivalent to: 4* (2^3) => 4*8 =32 
	ConvertToInt converts BigBinaryInteger a to integer
*/

// TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)

TEST(method_left_shift_equals,shift_less_than_max_shift){

	BigBinaryInteger a("39960");
	usshort num = 3;

	a<<=(num);
	int expectedResult = 319680;

	EXPECT_EQ(expectedResult, a.ConvertToInt());
}



// TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)

TEST(method_left_shift_equals,shift_greater_than_max_shift){

	BigBinaryInteger a("39960");
	usshort num = 6;

	a<<=(num);
	int expectedResult = 2557440;

	EXPECT_EQ(expectedResult, a.ConvertToInt());
}




/*--------------TESTING OPERATOR RIGHT SHIFT (>>) FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Right Shift" operates on BigBinary Integer a, and it is shifted by a number
  	Returns:  a>>(num), and the result is stored in BigBinary Integer calculatedResult
		"a" is right shifted by "num" number of bits, and filled up by 0s from left
		which is equivalent to a / (2^num)

		ex:4>>3 => (100000)>>3 => (000100) => 4
		this is equivalent to: 32*(2^3) => 32/8 = 4 
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/

// TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)

TEST(method_right_shift,shift_less_than_max_shift){

	BigBinaryInteger a("39965675");
	usshort shift = 3;

	BigBinaryInteger calculatedResult = a>>(shift);
	int expectedResult = 4995709;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}



// TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)

TEST(method_right_shift,shift_greater_than_max_shift){

	BigBinaryInteger a("39965675");
	usshort shift = 6;

	BigBinaryInteger calculatedResult = a>>(shift);
	int expectedResult = 624463;

	EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt());
}




/*--------------TESTING OPERATOR RIGHT SHIFT EQUALS(>>=) FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Right Shift Equals" operates on BigBinary Integer a, and it is shifted by a number
  	Returns:  a>>=(num), and the result is stored in a
		"a" is right shifted by "num" number of bits, and filled up by 0s from left
		which is equivalent to a / (2^num)

		ex:4>>3 => (100000)>>3 => (000100) => 4
		this is equivalent to: 32*(2^3) => 32/8 = 4 
	ConvertToInt converts BigBinaryInteger calculatedResult to integer
*/



// TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)

TEST(method_right_shift_equals,shift_less_than_max_shift){

	BigBinaryInteger a("39965675");
	usshort shift = 3;

	a>>=(shift);
	int expectedResult = 4995709;

	EXPECT_EQ(expectedResult, a.ConvertToInt());
}



// TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)

TEST(method_right_shift_equals,shift_greater_than_max_shift){

	BigBinaryInteger a("39965675");
	usshort shift = 6;

	a>>=(shift);
	int expectedResult = 624463;

	EXPECT_EQ(expectedResult, a.ConvertToInt());
}






