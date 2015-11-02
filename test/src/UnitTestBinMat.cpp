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

#include <gtest/gtest.h>
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





/*---------------------------------------	TESTING METHODS OF BINMAT CLASS		--------------------------------------------*/


/*--------------TESTING METHOD KRONECKER PRODUCT FOR ALL CONDITIONS---------------------------*/


/*TEST(binmat_method_kronecker, test_kronecker_product){
	
	BigBinaryMatrix a(3,3);	

	a.SetValAtIndex(0,0,"4");
	a.SetValAtIndex(0,1,"9");
	a.SetValAtIndex(0,2,"6");
	a.SetValAtIndex(1,0,"3");
	a.SetValAtIndex(1,1,"7");
	a.SetValAtIndex(1,2,"4");
	a.SetValAtIndex(2,0,"8");
	a.SetValAtIndex(2,1,"2");
	a.SetValAtIndex(2,2,"5");

	BigBinaryMatrix b(3,3);

	b.SetValAtIndex(0,0,"12");
	b.SetValAtIndex(0,1,"15");
	b.SetValAtIndex(0,2,"9");
	b.SetValAtIndex(1,0,"4");
	b.SetValAtIndex(1,1,"6");
	b.SetValAtIndex(1,2,"23");
	b.SetValAtIndex(2,0,"45");
	b.SetValAtIndex(2,1,"56");
	b.SetValAtIndex(2,2,"8");


	BigBinaryMatrix c(9,9);
	c = a.KroneckerProduct(b);

	int i,j;
	usint rindex, cindex;
	int expectedResult[9,9] = {};

	for (rindex=0;rindex<9;rindex++){
		for(cindex=0;cindex<9;cindex++)		
		{
			cout << "\n"<< rindex <<","<< cindex <<":"<<(c.GetValAtIndex(rindex,cindex)).ConvertToInt()<<"\n";
			EXPECT_EQ(expectedResult[i][j], (c.GetValAtIndex(rindex,cindex)).ConvertToInt());
		}
	}	
}*/



/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/*
TEST(binmat_method_modadd, test_binmat_modadd){
	BigBinaryMatrix a(3,3);	

	a.SetValAtIndex(0,0,"4");
	a.SetValAtIndex(0,1,"9");
	a.SetValAtIndex(0,2,"6");
	a.SetValAtIndex(1,0,"3");
	a.SetValAtIndex(1,1,"7");
	a.SetValAtIndex(1,2,"4");
	a.SetValAtIndex(2,0,"8");
	a.SetValAtIndex(2,1,"2");
	a.SetValAtIndex(2,2,"5");

	BigBinaryMatrix b(3,3);

	b.SetValAtIndex(0,0,"12");
	b.SetValAtIndex(0,1,"15");
	b.SetValAtIndex(0,2,"9");
	b.SetValAtIndex(1,0,"4");
	b.SetValAtIndex(1,1,"6");
	b.SetValAtIndex(1,2,"23");
	b.SetValAtIndex(2,0,"45");
	b.SetValAtIndex(2,1,"56");
	b.SetValAtIndex(2,2,"8");

	a.SetModulus("7");
	
	std::cout << "Before : " << std::endl;
	
	a.ModAdd(b); 

	std::cout << "Between : " << std::endl;

	BigBinaryMatrix c(a.ModAdd(b));

	std::cout << "After : " << std::endl;

	int i,j;
	usint rindex, cindex;
	int expectedResult[3][3] = {{2,3,1},{0,6,6},{4,2,6}};

	for (rindex=0;rindex<3;rindex++){
		for(cindex=0;cindex<3;cindex++)		
		{
			cout << "\n"<< rindex <<","<< cindex <<":"<<(c.GetValAtIndex(rindex,cindex)).ConvertToInt()<<"\n";
			EXPECT_EQ(expectedResult[i][j], (c.GetValAtIndex(rindex,cindex)).ConvertToInt());
		}
	}		
}
*/

/*--------------TESTING METHOD MODSUB FOR ALL CONDITIONS---------------------------*/

/*
TEST(binmat_method_modsub,test_binmat_modsub){
	BigBinaryMatrix a(3,3);	

	a.SetValAtIndex(0,0,"14");
	a.SetValAtIndex(0,1,"19");
	a.SetValAtIndex(0,2,"16");
	a.SetValAtIndex(1,0,"13");
	a.SetValAtIndex(1,1,"17");
	a.SetValAtIndex(1,2,"44");
	a.SetValAtIndex(2,0,"78");
	a.SetValAtIndex(2,1,"92");
	a.SetValAtIndex(2,2,"55");

	BigBinaryMatrix b(3,3);

	b.SetValAtIndex(0,0,"12");
	b.SetValAtIndex(0,1,"15");
	b.SetValAtIndex(0,2,"9");
	b.SetValAtIndex(1,0,"4");
	b.SetValAtIndex(1,1,"6");
	b.SetValAtIndex(1,2,"23");
	b.SetValAtIndex(2,0,"45");
	b.SetValAtIndex(2,1,"56");
	b.SetValAtIndex(2,2,"8");

	a.SetModulus("7");

	BigBinaryMatrix c(3,3);
	c = a.ModSub(b);

	int i,j;
	usint rindex, cindex;
	int expectedResult[3][3] = {{2,4,0},{2,4,0},{5,1,5}};

	for (rindex=0;rindex<3;rindex++){
		for(cindex=0;cindex<3;cindex++)		
		{
			cout << "\n"<< rindex <<","<< cindex <<":"<<(c.GetValAtIndex(rindex,cindex)).ConvertToInt()<<"\n";
			EXPECT_EQ(expectedResult[i][j], (c.GetValAtIndex(rindex,cindex)).ConvertToInt());
		}
	}		
}*/

/*---------------------------------------	END OF TEST CODES	-------------------------------------------------------*/

