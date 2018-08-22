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
 /*
	This code exercises the math libraries of the PALISADE lattice encryption library.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "../lib/lattice/dcrtpoly.h"
#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "utils/utilities.h"
#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

/*---------------------------------------	TESTING METHODS OF BINVECT CLASS		--------------------------------------------*/



//---------------------TESTING INTEGER OPERATIONS ON VECTOR---------------------------------//

/*
	at() operates on Big Vector, retrieves the value at the given index of a vector
	The functions returns BigInteger, which is passed to ConvertToInt() to convert to integer
	One dimensional integer array expectedResult is created
	Indivdual expected result for each index of the vector is store in array
	EXPECT_EQ is given the above integer from at, and the value of the expectedResult at the corresponding index
*/





/*--------------TESTING METHOD MODULUS FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod" operates on Big Vector m, BigInteger q
  	Returns:  m mod q, and the result is stored in Big Vector calculatedResult.
*/
template<typename V>
void AtAndSetModulusTest(const string& msg) {
	bool dbg_flag = false;
	usint len = 10;
	V m(len);

	//note at() does not set modulus
	m.at(0) = typename V::Integer("987968");
	m.at(1) = typename V::Integer("587679");
	m.at(2) = typename V::Integer("456454");
	m.at(3) = typename V::Integer("234343");
	m.at(4) = typename V::Integer("769789");
	m.at(5) = typename V::Integer("465654");
	m.at(6) = typename V::Integer("79");
	m.at(7) = typename V::Integer("346346");
	m.at(8) = typename V::Integer("325328");
	m.at(9) = typename V::Integer("7698798");

	typename V::Integer q("233");

	m.SetModulus(q);

	DEBUG("m"<<m);
	V calculatedResult = m.Mod(q);
	DEBUG("calculated result"<<m);
	uint64_t expectedResult[] = {48,53,7,178,190,120,79,108,60,12};
	for (usint i=0;i<len;i++){
	  EXPECT_EQ (expectedResult[i],calculatedResult[i].ConvertToInt())
	    << msg << " Mod failed";
	}
	V n(len,q);
	
	n.at(0) = typename V::Integer("987968"); //note at() does not take modulus
	n.at(1) = typename V::Integer("587679");
	n.at(2) = typename V::Integer("456454");
	n.at(3) = typename V::Integer("234343");
	n.at(4) = typename V::Integer("769789");
	n.at(5) = typename V::Integer("465654");
	n.at(6) = typename V::Integer("79");
	n.at(7) = typename V::Integer("346346");
	n.at(8) = typename V::Integer("325328");
	n.at(9) = typename V::Integer("7698798");

	DEBUG("n"<<n);
	for (usint i=0;i<len;i++){
		if (i !=6){ // value at 6 is < q
		  EXPECT_NE (expectedResult[i],n[i].ConvertToInt())
		    << msg << " at no mod failed";
		}else{
		  EXPECT_EQ (expectedResult[i],n[i].ConvertToInt())
		    << msg << " at no mod failed";
		}
	}

	n.atMod(0,"987968"); //note atMod() does take modulus
	n.atMod(1,"587679");
	n.atMod(2,"456454");
	n.atMod(3,"234343");
	n.atMod(4,"769789");
	n.atMod(5,"465654");
	n.atMod(6,"79");
	n.atMod(7,"346346");
	n.atMod(8,"325328");
	n.atMod(9,"7698798");	

	for (usint i=0;i<len;i++){
	  EXPECT_EQ (expectedResult[i], n[i].ConvertToInt())
	    << "atMod failed";
	}
	V l(len,q);
	//note list assignment does take modulus
	l = {"987968", 
	     "587679",
	     "456454",
	     "234343",
	     "769789",
	     "465654",
	     "79",
	     "346346",
	     "325328",
	     "7698798"};	
	DEBUG("l"<<l);
	for (usint i=0;i<len;i++){	
	  EXPECT_EQ (expectedResult[i], l[i].ConvertToInt())
	    << msg << " Mod on list assignment failed";
	}
}

TEST(UTBinVect,AtAndSetModulusTest) {
	{ using V = M2Vector; AtAndSetModulusTest<V>("BE2 AtAndSetModulusTest"); }
	{ using V = M4Vector; AtAndSetModulusTest<V>("BE4 AtAndSetModulusTest"); }
	{ using V = M6Vector; AtAndSetModulusTest<V>("BE6 AtAndSetModulusTest"); }
	{ using V = NativeVector; AtAndSetModulusTest<V>("Native AtAndSetModulusTest"); }
}

#ifdef OUT // i think this is redundant?
template<typename V>
void NTL_modulus_framework(const string& msg) {
	
  bool dbg_flag = false;
	
  //code to test that the modulus framwork is ok
  
  NTL::myZZ q1("1234567"); // a bigger number
  NTL::myZZ q2("345"); // a smaller bigger number

  NTL::myVecP<NTL::myZZ>  m(5); 
  m = {"9868", "5879", "4554", "2343", "4624",}; 
  vector<usint> m_expected_1 = {9868, 5879, 4554, 2343, 4624,}; 

  m.SetModulus(q1);

  //test the modulus of the entire vector.
  NTL::myZZ qtest1 = m.GetModulus();
  DEBUG("m "<<m);
  DEBUG("q1 "<<q1);
  DEBUG("qtest1 "<<qtest1);
  EXPECT_EQ(q1, qtest1)<<"Failure NTL vector.GetModulus() 1";

  for (size_t i = 0; i < m.GetLength(); i++){
    EXPECT_EQ(m_expected_1[i],m[i].ConvertToInt()) << "Failure in NTL ["<<i<<"]";
  }
  NTL::myZZ elem = m[0]; 

  EXPECT_EQ(9868U,elem.ConvertToInt()) << "Failure in NTL elem 1";

  //now switch the modulus.
  m.SetModulus(q2);
  //but the vector values do not get updated!

  //test the modulus of the entire vector.
  NTL::myZZ qtest2 = m.GetModulus();
  DEBUG("m "<<m);
  DEBUG("q2 "<<q2);
  DEBUG("qtest2 "<<qtest2);
  vector<usint> m_modulus_2 = {208, 14, 69, 273, 139,}; 
  EXPECT_EQ(q2, qtest2)<<"Failure NTL vector.GetModulus() 2";

  for (size_t i = 0; i < m.GetLength(); i++){
    EXPECT_NE(m_modulus_2[i],m[i].ConvertToInt()) << "Failure in NTL ["<<i<<"]";
  }
}

TEST(UTBinVect,AtAndSetModulusTest) {
	{ using V = M2Vector; AtAndSetModulusTest<V>("BE2 AtAndSetModulusTest"); }
	{ using V = M4Vector; AtAndSetModulusTest<V>("BE4 AtAndSetModulusTest"); }
	{ using V = M6Vector; AtAndSetModulusTest<V>("BE6 AtAndSetModulusTest"); }
	{ using V = NativeVector; AtAndSetModulusTest<V>("Native AtAndSetModulusTest"); }
}
#endif

template<typename V>
void CTOR_Test(const string& msg) {

	typename V::Integer q("233");
	usint expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};
	const usint len = sizeof(expectedResult)/sizeof(expectedResult[0]);

	{
		V m(len, q,
				{"987968","587679","456454","234343",
						"769789","465654","79","346346",
						"325328","7698798"});

		V calculatedResult = m.Mod(q);


		for (usint i=0;i<len;i++){
			EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
		}
	}

	{
		V m(len, q,  {48,53,7,178,190,120,79,108,60,12});

		for (usint i=0;i<len;i++){
			EXPECT_EQ (expectedResult[i], m.at(i).ConvertToInt()) << msg;
		}

	}
}

TEST(UTBinVect,CTOR_Test) {
	{ using V = M2Vector; CTOR_Test<V>("BE2 CTOR_Test"); }
	{ using V = M4Vector; CTOR_Test<V>("BE4 CTOR_Test"); }
	{ using V = M6Vector; CTOR_Test<V>("BE6 CTOR_Test"); }
	{ using V = NativeVector; CTOR_Test<V>("Native CTOR_Test"); }
}

/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Add" operates on Big Vector m, BigIntegers n,q
  	Returns:  (m+n)mod q, and the result is stored in Big Vector calculatedResult.
*/

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS 

template<typename V>
void ModAddBigModulus(const string& msg) {

	typename V::Integer q("3435435");	// constructor calling to set mod value
	V m(5,q);		// calling constructor to create a vector of length 5 and passing value of q
	typename V::Integer n("3");

	//at() is ok since q is bigger than values
	m.at(0) = typename V::Integer("9868");
	m.at(1) = typename V::Integer("5879");
	m.at(2) = typename V::Integer("4554");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("9789");

	V calculatedResult = m.ModAdd(n);

	uint64_t expectedResult[5] = {9871, 5882, 4557, 2346, 9792};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}

}

TEST(UTBinVect,ModAddBigModulus) {
	{ using V = M2Vector; ModAddBigModulus<V>("BE2 ModAddBigModulus"); }
	{ using V = M4Vector; ModAddBigModulus<V>("BE4 ModAddBigModulus"); }
	{ using V = M6Vector; ModAddBigModulus<V>("BE6 ModAddBigModulus"); }
	{ using V = NativeVector; ModAddBigModulus<V>("Native ModAddBigModulus"); }
}

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS 

template<typename V>
void ModAddSmallerModulus(const string& msg) {
  bool dbg_flag = false;

  {
	  NativeInteger A = 9868;
	  NativeInteger M = 3534;
	  NativeInteger N = 34365;

	  cout << "NTL_BITS_PER_LONG " << NTL_BITS_PER_LONG << endl;
	  cout << A << ", ";
	  cout << M << ", ";
	  cout << N << endl;
	  cout << "A.ModAdd(N,M): ";
	  cout << A.ModAdd(N,M) << endl;

	  A = 9868;
	  cout << "A.ModAddFast(N,M) ";
	  cout << A.ModAddFast(N,M) << endl;

	  A = 9868;
	  cout << "A.ModAddFastOptimizedEq(N,M) ";
	  cout << A.ModAddFastOptimizedEq(N,M) << endl;

	  A = 9868;
	  cout << "NTL Call: ";
	  cout << NTL::AddMod(A.ConvertToInt(), N.ConvertToInt(), M.ConvertToInt()) << endl;
  }

	typename V::Integer q("3534");	// constructor calling to set mod value
	V m(5,q);		// calling constructor to create a vector of length 5 and passing value of q
	typename V::Integer n("34365");

	DEBUG("m "<<m);
	DEBUG("m's modulus "<<m.GetModulus());
	//at() does not apply mod. 
	m.at(0) = typename V::Integer("9868");
	m.at(1) = typename V::Integer("5879");
	m.at(2) = typename V::Integer("4554");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("9789");
	
	V calculatedResult = m.ModAdd(n);

	DEBUG("m "<<m);
	DEBUG("calculated result  "<< calculatedResult);
	uint64_t expectedResult[5] = {1825,1370,45,1368,1746};
	
	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}
}

TEST(UTBinVect,ModAddSmallerModulus) {
	{ using V = M2Vector; ModAddSmallerModulus<V>("BE2 ModAddSmallerModulus"); }
	{ using V = M4Vector; ModAddSmallerModulus<V>("BE4 ModAddSmallerModulus"); }
	{ using V = M6Vector; ModAddSmallerModulus<V>("BE6 ModAddSmallerModulus"); }
	{ using V = NativeVector; ModAddSmallerModulus<V>("Native ModAddSmallerModulus"); }
}

/*--------------TESTING METHOD MODUSUB FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Sub" operates on Big Vector m, BigIntegers n,q
  	Returns:  
		when m>n, (m-n)mod q
		when m=n, 0 
		when m<n, {(m mod q)+q-(n mod q)} mod q
	and the result is stored in Big Vector calculatedResult.
*/

// TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER 

template<typename V>
void modsub_first_less_than_second(const string& msg) {

	typename V::Integer q("3534");			// constructor calling to set mod value
	V m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	typename V::Integer n("34365");

	m.at(0) = typename V::Integer("9868");
	m.at(1) = typename V::Integer("5879");
	m.at(2) = typename V::Integer("4554");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("9789");
	
	V calculatedResult = m.ModSub(n);

	uint64_t expectedResult[5] = {241,3320,1995,3318,162};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}
}

TEST(UTBinVect,modsub_first_less_than_second) {
	{ using V = M2Vector; modsub_first_less_than_second<V>("BE2 modsub_first_less_than_second"); }
	{ using V = M4Vector; modsub_first_less_than_second<V>("BE4 modsub_first_less_than_second"); }
	{ using V = M6Vector; modsub_first_less_than_second<V>("BE6 modsub_first_less_than_second"); }
	{ using V = NativeVector; modsub_first_less_than_second<V>("Native modsub_first_less_than_second"); }
}

// TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER 

template<typename V>
void modsub_first_greater_than_second(const string& msg) {

	typename V::Integer q("35");	// constructor calling to set mod value
	V m(5,q);		// calling constructor to create a vector of length 5 and passing value of q
	typename V::Integer n("765");
	
	m.at(0) = typename V::Integer("9868");
	m.at(1) = typename V::Integer("5879");
	m.at(2) = typename V::Integer("4554");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("9789");
	
	V calculatedResult = m.ModSub(n);

	uint64_t expectedResult[5] = {3,4,9,3,29};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}
}

TEST(UTBinVect,modsub_first_greater_than_second) {
	{ using V = M2Vector; modsub_first_greater_than_second<V>("BE2 modsub_first_greater_than_second"); }
	{ using V = M4Vector; modsub_first_greater_than_second<V>("BE4 modsub_first_greater_than_second"); }
	{ using V = M6Vector; modsub_first_greater_than_second<V>("BE6 modsub_first_greater_than_second"); }
	{ using V = NativeVector; modsub_first_greater_than_second<V>("Native modsub_first_greater_than_second"); }
}

/*--------------TESTING METHOD MODUMUL FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Mul" operates on Big Vector m, BigIntegers n,q
  	Returns:  (m*n)mod q
	and the result is stored in Big Vector calculatedResult.
*/
template<typename V>
void ModMulTest(const string& msg) {

	typename V::Integer q("3534");			// constructor calling to set mod value
	V m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	typename V::Integer n("46");

	m.at(0) = typename V::Integer("9868");
	m.at(1) = typename V::Integer("5879");
	m.at(2) = typename V::Integer("4554");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("9789");

	V calculatedResult = m.ModMul(n);

	uint64_t expectedResult[5] = {1576,1850,978,1758,1476};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}
}

TEST(UTBinVect,ModMulTest) {
	{ using V = M2Vector; ModMulTest<V>("BE2 ModMulTest"); }
	{ using V = M4Vector; ModMulTest<V>("BE4 ModMulTest"); }
	{ using V = M6Vector; ModMulTest<V>("BE6 ModMulTest"); }
	{ using V = NativeVector; ModMulTest<V>("Native ModMulTest"); }
}

/*--------------TESTING METHOD MODEXP FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Exp" operates on Big Vector m, BigIntegers n,q
  	Returns:  (m^n)mod q
	and the result is stored in Big Vector calculatedResult.
*/
template<typename V>
void ModExpTest(const string& msg) {
  bool dbg_flag = false;
	typename V::Integer q("3534");			// constructor calling to set mod value
	V m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	typename V::Integer n("3");

	m.at(0) = typename V::Integer("968");
	m.at(1) = typename V::Integer("579");
	m.at(2) = typename V::Integer("4");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("97");
	DEBUG("m's modulus "<<m.GetModulus());
	
	V calculatedResult = m.ModExp(n);

	uint64_t expectedResult[5] = {2792,3123,64,159,901};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}
}

TEST(UTBinVect,ModExpTest) {
	{ using V = M2Vector; ModExpTest<V>("BE2 ModExpTest"); }
	{ using V = M4Vector; ModExpTest<V>("BE4 ModExpTest"); }
	{ using V = M6Vector; ModExpTest<V>("BE6 ModExpTest"); }
	{ using V = NativeVector; ModExpTest<V>("Native ModExpTest"); }
}

/*--------------TESTING METHOD MODINVERSE FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod ModInverse" operates on Big Vector m, BigInteger q
  	Returns:  (m^(-1))mod q
		when m and q are co-prime (i,e GCD of m and q is 1)
		and is calculated using extended Eucleadian Algorithm
	and the result is stored in Big Vector calculatedResult.
*/
template<typename V>
void test_modinv(const string& msg) {

	typename V::Integer q("35");			// constructor calling to set mod value
	V m(5,q);				// calling constructor to create a vector of length 5 and passing value of q

	m.at(0) = typename V::Integer("968");
	m.at(1) = typename V::Integer("579");
	m.at(2) = typename V::Integer("4");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("97");
	
	V calculatedResult = m.ModInverse();

	uint64_t expectedResult[5] = {32,24,9,17,13};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}

}

TEST(UTBinVect,test_modinv) {
	{ using V = M2Vector; test_modinv<V>("BE2 test_modinv"); }
	{ using V = M4Vector; test_modinv<V>("BE4 test_modinv"); }
	{ using V = M6Vector; test_modinv<V>("BE6 test_modinv"); }
	{ using V = NativeVector; test_modinv<V>("Native test_modinv"); }
}

/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Add" operates on Big Vectors m,n BigInteger q
  	Returns:  (m+n)mod q, and the result is stored in Big Vector calculatedResult.
*/


// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS 

template<typename V>
void modadd_vector_result_smaller_modulus(const string& msg) {
		
	typename V::Integer q("878870");		// constructor calling to set mod value
	V m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	V n(5,q);

	m.at(0) = typename V::Integer("9868");
	m.at(1) = typename V::Integer("5879");
	m.at(2) = typename V::Integer("4554");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("9789");

	n.at(0) = typename V::Integer("4533");
	n.at(1) = typename V::Integer("4549");
	n.at(2) = typename V::Integer("6756");
	n.at(3) = typename V::Integer("1233");
	n.at(4) = typename V::Integer("7897");
	
	V calculatedResult = m.ModAdd(n);

	uint64_t expectedResult[5] = {14401,10428,11310,3576,17686};

	for (usint i=0;i<5;i++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}
}

TEST(UTBinVect,modadd_vector_result_smaller_modulus) {
	{ using V = M2Vector; modadd_vector_result_smaller_modulus<V>("BE2 modadd_vector_result_smaller_modulus"); }
	{ using V = M4Vector; modadd_vector_result_smaller_modulus<V>("BE4 modadd_vector_result_smaller_modulus"); }
	{ using V = M6Vector; modadd_vector_result_smaller_modulus<V>("BE6 modadd_vector_result_smaller_modulus"); }
	{ using V = NativeVector; modadd_vector_result_smaller_modulus<V>("Native modadd_vector_result_smaller_modulus"); }
}

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS 

template<typename V>
void modadd_vector_result_greater_modulus(const string& msg) {
    bool dbg_flag = false;
	typename V::Integer q("657");		// constructor calling to set mod value
	V m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	V n(5,q);
	
	m = {"9868","5879","4554","2343","9789"};

	n={"4533", "4549", "6756", "1233", "7897"};
	
	DEBUG("m "<<m);
	DEBUG("m mod"<<m.GetModulus());
	DEBUG("n "<<n);
	DEBUG("n mod "<<n.GetModulus());

	V calculatedResult = m.ModAdd(n);

	DEBUG("result mod "<<calculatedResult.GetModulus());	
	uint64_t expectedResult[5] = {604,573,141,291,604};

	for (usint i=0;i<5;i++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}

}

TEST(UTBinVect,modadd_vector_result_greater_modulus) {
	{ using V = M2Vector; modadd_vector_result_greater_modulus<V>("BE2 modadd_vector_result_greater_modulus"); }
	{ using V = M4Vector; modadd_vector_result_greater_modulus<V>("BE4 modadd_vector_result_greater_modulus"); }
	{ using V = M6Vector; modadd_vector_result_greater_modulus<V>("BE6 modadd_vector_result_greater_modulus"); }
	{ using V = NativeVector; modadd_vector_result_greater_modulus<V>("Native modadd_vector_result_greater_modulus"); }
}

/*--------------TESTING METHOD PLUS EQUALS FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Plus Equals" operates on Big Vectors m,n BigInteger q
  	Returns:  (m+n)mod q, and the result is stored in Big Vector a.
*/
template<typename V>
void method_plus_equals_vector_operation(const string& msg) {
	bool dbg_flag = false;
	typename V::Integer q("657");
	V m(5,q); // calling constructor to create a vector of length 5 and passing value of q
	V n(5,q);
	
	m = {"9868", "5879", "4554", "2343", "9789"};

	n.at(0) = typename V::Integer("4"); //note at does not allow uses of modulus.
	n.at(1) = typename V::Integer("9");
	n.at(2) = typename V::Integer("66");
	n.at(3) = typename V::Integer("33");
	n.at(4) = typename V::Integer("7");
 
	DEBUG("m "<<m);
	DEBUG("n "<<n);
	
	m+=n;
	DEBUG("m" <<m);
	uint64_t expectedResult[5] = {17,632,21,405,598};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (m.at(i)).ConvertToInt()) << msg;
	}
}

TEST(UTBinVect,method_plus_equals_vector_operation) {
	{ using V = M2Vector; method_plus_equals_vector_operation<V>("BE2 method_plus_equals_vector_operation"); }
	{ using V = M4Vector; method_plus_equals_vector_operation<V>("BE4 method_plus_equals_vector_operation"); }
	{ using V = M6Vector; method_plus_equals_vector_operation<V>("BE6 method_plus_equals_vector_operation"); }
	{ using V = NativeVector; method_plus_equals_vector_operation<V>("Native method_plus_equals_vector_operation"); }
}

/*--------------TESTING METHOD MODMUL FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Mod Mul" operates on Big Vectors m,n BigInteger q
  	Returns:  (m*n)mod q, and the result is stored in Big Vector a.
*/

template<typename V>
void modmul_vector(const string& msg) {

	typename V::Integer q("657");		// constructor calling to set mod value
	V m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	V n(5,q);

	m.at(0) = typename V::Integer("9868");
	m.at(1) = typename V::Integer("5879");
	m.at(2) = typename V::Integer("4554");
	m.at(3) = typename V::Integer("2343");
	m.at(4) = typename V::Integer("9789");

	n.at(0) = typename V::Integer("4");
	n.at(1) = typename V::Integer("9");
	n.at(2) = typename V::Integer("66");
	n.at(3) = typename V::Integer("33");
	n.at(4) = typename V::Integer("7");
	
	V calculatedResult = m.ModMul(n);

	uint64_t expectedResult[5] = {52,351,315,450,195};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
	}
}

TEST(UTBinVect,modmul_vector) {
	{ using V = M2Vector; modmul_vector<V>("BE2 modmul_vector"); }
	{ using V = M4Vector; modmul_vector<V>("BE4 modmul_vector"); }
	{ using V = M6Vector; modmul_vector<V>("BE6 modmul_vector"); }
	{ using V = NativeVector; modmul_vector<V>("Native modmul_vector"); }
}
