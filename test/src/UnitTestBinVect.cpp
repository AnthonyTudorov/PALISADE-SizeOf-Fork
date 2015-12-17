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

#include "../include/gtest/gtest.h"
#include <iostream>

#include "../../src/math/backend.h"
#include "../../src/utils/inttypes.h"
#include "../../src/math/nbtheory.h"
#include "../../src/lattice/elemparams.h"
#include "../../src/lattice/ilparams.h"
#include "../../src/lattice/ildcrtparams.h"
#include "../../src/lattice/ilelement.h"
#include "../../src/math/distrgen.h"
#include "../../src/crypto/lwecrypt.h"
#include "../../src/crypto/lwepre.h"
#include "../../src/lattice/il2n.h"
#include "../../src/utils/utilities.h"

using namespace std;
using namespace lbcrypto;

/*
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
*/


/*
EXPECT_EQ (expected, actual) verifies expected == actual.
Compares two integer values
*/





/*---------------------------------------	TESTING METHODS OF BINVECT CLASS		--------------------------------------------*/



//---------------------TESTING INTEGER OPERATIONS ON VECTOR---------------------------------//

/*
	GetValAtIndex() operates on BigBinary Vector, retrieves the value at the given index of a vector
	The functions returns BigBinaryInterger, which is passed to ConvertToInt() to convert to integer
	One dimensional integer array expectedResult is created
	Indivdual expected result for each index of the vector is store in array
	EXPECT_EQ is given the above integer from GetValAtIndex, and the value of the expectedResult at the corresponding index
*/





/*--------------TESTING METHOD MODULUS FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod" operates on BigBinary Vector m, BigBinary Integer q
  	Returns:  m mod q, and the result is stored in BigBinary Vector calculatedResult.
*/

TEST(method_mod_vect,test_modulus){

	BigBinaryVector m(10);				// calling constructor to create a vector of length 10

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
	

	BigBinaryInteger q("233");		//calling costructor of BigBinaryInteger Class to create object for modulus

	BigBinaryVector calculatedResult = m.Mod(q);

	int expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};	// the expected values are stored as one dimensional integer array

	for (i=0,j=0;i<10;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}

}


/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Add" operates on BigBinary Vector m, BigBinary Integers n,q
  	Returns:  (m+n)mod q, and the result is stored in BigBinary Vector calculatedResult.
*/

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS 

TEST(method_modadd_vect,modadd_result_smaller_than_modulus){
	

	BigBinaryInteger q("3435435");	// constructor calling to set mod value
	BigBinaryVector m(5,q);		// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryInteger n("3");

	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");

	
	BigBinaryVector calculatedResult = m.ModAdd(n);

	int expectedResult[5] = {9871,5879,4554,2343,9789};

	for (i=0,j=0;i<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}

}


// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS 

TEST(method_modadd_vect,modadd_result_greater_than_modulus){

	BigBinaryInteger q("3534");	// constructor calling to set mod value
	BigBinaryVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryInteger n("34365");

	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");
	
	BigBinaryVector calculatedResult = m.ModAdd(n);


	int expectedResult[5] = {1825,5879,4554,2343,9789};

	for (i=0,j=0;i<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}

}


/*--------------TESTING METHOD MODUSUB FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Sub" operates on BigBinary Vector m, BigBinary Integers n,q
  	Returns:  
		when m>n, (m-n)mod q
		when m=n, 0 
		when m<n, {(m mod q)+q-(n mod q)} mod q
	and the result is stored in BigBinary Vector calculatedResult.
*/

// TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER 

TEST(method_modsub_vect,modsub_first_number_less_than_second_number){

	BigBinaryInteger q("3534");			// constructor calling to set mod value
	BigBinaryVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryInteger n("34365");

	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");
	
	BigBinaryVector calculatedResult = m.ModSub(n);

	int expectedResult[5] = {241,3320,1995,3318,162};

	for (i=0,j=0;i<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}

}



// TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER 

TEST(method_modsub_vect,modsub_first_number_greater_than_second_number){

	BigBinaryInteger q("35");	// constructor calling to set mod value
	BigBinaryVector m(5,q);		// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryInteger n("765");
	
	int i;
	usint j;
	
	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");
	
	BigBinaryVector calculatedResult = m.ModSub(n);

	int expectedResult[5] = {3,4,9,3,29};

	for (i=0,j=0;i<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}

}


/*--------------TESTING METHOD MODUMUL FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Mod" operates on BigBinary Vector m, BigBinary Integers n,q
  	Returns:  (m*n)mod q
	and the result is stored in BigBinary Vector calculatedResult.
*/

TEST(method_modmul_vect,test_modmul){

	BigBinaryInteger q("3534");			// constructor calling to set mod value
	BigBinaryVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryInteger n("46");

	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");

	// std::cout << "Before : " << std::endl;
	
	BigBinaryVector calculatedResult = m.ModMul(n);

	// std::cout << "After : " << std::endl;

	int expectedResult[5] = {1576,1850,978,1758,1476};

	for (i=0,j=0;j<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}
}



/*--------------TESTING METHOD MODEXP FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Exp" operates on BigBinary Vector m, BigBinary Integers n,q
  	Returns:  (m^n)mod q
	and the result is stored in BigBinary Vector calculatedResult.
*/


TEST(method_modexp_vect,test_modexp){

	BigBinaryInteger q("3534");			// constructor calling to set mod value
	BigBinaryVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryInteger n("3");
	
	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"968");
	m.SetValAtIndex(1,"579");
	m.SetValAtIndex(2,"4");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"97");
	
	BigBinaryVector calculatedResult = m.ModExp(n);

	int expectedResult[5] = {2792,3123,64,159,901};

	
	for (i=0,j=0;j<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}

}


/*--------------TESTING METHOD MODINVERSE FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod ModInverse" operates on BigBinary Vector m, BigBinary Integer q
  	Returns:  (m^(-1))mod q
		when m and q are co-prime (i,e GCD of m and q is 1)
		and is calculated using extended Eucleadian Algorithm
	and the result is stored in BigBinary Vector calculatedResult.
*/

TEST(method_modinv_vect,test_modinv){

	BigBinaryInteger q("35");			// constructor calling to set mod value
	BigBinaryVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
				
	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"968");
	m.SetValAtIndex(1,"579");
	m.SetValAtIndex(2,"4");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"97");
	
	BigBinaryVector calculatedResult = m.ModInverse();

	int expectedResult[5] = {32,24,9,17,13};

	
	for (i=0,j=0;j<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}

}



//-------------------END OF TESTING INTEGER OPERATIONS ON VECTOR---------------------------//




//---------------TESTING VECTOR OPERATIONS ON VECTOR----------------------------------------//


/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Add" operates on BigBinary Vectors m,n BigBinary Integer q
  	Returns:  (m+n)mod q, and the result is stored in BigBinary Vector calculatedResult.
*/


// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS 

TEST(method_modadd_vector, modadd_vector_result_smaller_modulus){
		
	BigBinaryInteger q("878870");		// constructor calling to set mod value
	BigBinaryVector m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryVector n(5);	
	
	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");


	//setting value of the value at different index locations
	n.SetValAtIndex(0,"4533");
	n.SetValAtIndex(1,"4549");
	n.SetValAtIndex(2,"6756");
	n.SetValAtIndex(3,"1233");
	n.SetValAtIndex(4,"7897");

	
	BigBinaryVector calculatedResult = m.ModAdd(n);

	int expectedResult[5] = {14401,10428,11310,3576,17686};

	for (i=0,j=0;j<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}


}


// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS 

TEST(method_modadd_vector, modadd_vector_result_greater_modulus){

	BigBinaryInteger q("657");		// constructor calling to set mod value
	BigBinaryVector m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryVector n(5);	
	
	int i;
	usint j;
	
	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");


	//setting value of the value at different index locations
	n.SetValAtIndex(0,"4533");
	n.SetValAtIndex(1,"4549");
	n.SetValAtIndex(2,"6756");
	n.SetValAtIndex(3,"1233");
	n.SetValAtIndex(4,"7897");
	//a.SetValAtIndex(4,"8745");
	
	BigBinaryVector calculatedResult = m.ModAdd(n);

	int expectedResult[5] = {604,573,141,291,604};

	for (i=0,j=0;j<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}

}


/*--------------TESTING METHOD PLUS EQUALS FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Plus Equals" operates on BigBinary Vectors m,n BigBinary Integer q
  	Returns:  (m+n)mod q, and the result is stored in BigBinary Vector a.
*/

TEST(method_plus_equals_vector,method_plus_equals){
	BigBinaryInteger q("657");	
	BigBinaryVector m(5,q); // calling constructor to create a vector of length 5 and passing value of q
	BigBinaryVector n(5);
	
	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");


	//setting value of the value at different index locations
	n.SetValAtIndex(0,"4");
	n.SetValAtIndex(1,"9");
	n.SetValAtIndex(2,"66");
	n.SetValAtIndex(3,"33");
	n.SetValAtIndex(4,"7");

	m+=n;

	int expectedResult[5] = {17,632,21,405,598};

	for (i=0,j=0;j<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (m.GetValAtIndex(j)).ConvertToInt());
	}
}


/*--------------TESTING METHOD MODMUL FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Mod Mul" operates on BigBinary Vectors m,n BigBinary Integer q
  	Returns:  (m*n)mod q, and the result is stored in BigBinary Vector a.
*/

TEST(method_modmul_vector, modmul_vector){

	BigBinaryInteger q("657");		// constructor calling to set mod value
	BigBinaryVector m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryVector n(5);	

	int i;
	usint j;

	//setting value of the value at different index locations
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");


	//setting value of the value at different index locations
	n.SetValAtIndex(0,"4");
	n.SetValAtIndex(1,"9");
	n.SetValAtIndex(2,"66");
	n.SetValAtIndex(3,"33");
	n.SetValAtIndex(4,"7");
	
	
	BigBinaryVector calculatedResult = m.ModMul(n);

	int expectedResult[5] = {52,351,315,450,195};

	for (i=0,j=0;j<5;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}


}



/*--------------TESTING METHOD MODMATRIXMUL FOR ALL CONDITIONS---------------------------*/

/*TEST(method_mod_matrix_mul_vector, mod_matrix_mul_vector){

	BigBinaryInteger q("657");		// constructor calling to set mod value
	BigBinaryVector a(3,q);			// calling constructor to create a vector of length 5 and passing value of q
	BigBinaryMatrix b(3,3);	

	int i;
	usint j;

	//setting value of the value at different index locations
	a.SetValAtIndex(0,"966");
	a.SetValAtIndex(1,"567");
	a.SetValAtIndex(2,"466");
	

	//creating the matrix
	b.SetValAtIndex(0,0,"4");
	b.SetValAtIndex(0,1,"9");
	b.SetValAtIndex(0,2,"6");
	b.SetValAtIndex(1,0,"3");
	b.SetValAtIndex(1,1,"7");
	b.SetValAtIndex(1,2,"4");
	b.SetValAtIndex(2,0,"8");
	b.SetValAtIndex(2,1,"2");
	b.SetValAtIndex(2,2,"5");
	
	BigBinaryVector calculatedResult = a.ModMatrixMul(b);
	cout << calculatedResult<< "\n";
	int expectedResult[3] = {594,190,23};

	for (i=0,j=0;j<3;i++,j++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToInt());
	}


}*/
