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
/* NOTE THIS FILE WILL BE COMPLETELY REDONE SOON */


/*
  int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  }
*/

/************************************************/
/*	TESTING BASIC METHODS OF ubintvec CLASS        */
/************************************************/
//constructors
//ubintvec()
//ubintvec(usint)
//ubintvec(ubintvec)
//need memory test for destructor
/************************************************/
/*	TESTING BASIC operators OF ubintvec CLASS        */
/************************************************/
//=(binvect)
//=(bintvect&&)
//=usint



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

TEST(UTubintvec,mod_operations){

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
  int expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};	// the expected values are stored as one dimensional integer array

  for (i=0,j=0;i<10;i++,j++)
    {
      EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToUsint());
    }
}




//-------------------END OF TESTING INTEGER OPERATIONS ON VECTOR---------------------------//




//---------------TESTING VECTOR OPERATIONS ON VECTOR----------------------------------------//


/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Add" operates on BigBinary Vectors m,n BigBinary Integer q
  	Returns:  (m+n)mod q, and the result is stored in BigBinary Vector calculatedResult.
*/




/*--------------TESTING METHOD PLUS EQUALS FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Plus Equals" operates on BigBinary Vectors m,n BigBinary Integer q
  	Returns:  (m+n)mod q, and the result is stored in BigBinary Vector a.
*/

TEST(UTubintvec,basic_math){
  ubint q("657");
  ubintvec m(5); // calling constructor to create a vector of length 5
  ubintvec n(5);
	
  int i;
  usint j;

  //setting value of the value at different index locations
  m.SetValAtIndex(0,"9868");
  m.SetValAtIndex(1,"5879");
  m.SetValAtIndex(2,"4554");
  m.SetValAtIndex(3,"2343");
  m.SetValAtIndex(4,"4624");


  //setting value of the value at different index locations
  n.SetValAtIndex(0,"4");
  n.SetValAtIndex(1,"9");
  n.SetValAtIndex(2,"66");
  n.SetValAtIndex(3,"33");
  n.SetValAtIndex(4,"7");
  m+=n;
  int expectedResult[5] = {9872,5888,4620,2376,4631};

  for (i=0,j=0;j<5;i++,j++)
    {
      EXPECT_EQ (expectedResult[i], (m.GetValAtIndex(j)).ConvertToUsint())
	<< "Failure testing method_plus_equals";
    }
}


