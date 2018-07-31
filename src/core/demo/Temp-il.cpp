/*
 * Temp-il.cpp
 *
 *  Created on: Jul 31, 2018
 *      Author: gwryan
 */

#include <iostream>
using namespace std;

#include "math/backend.h"

using namespace lbcrypto;

enum LType { Native, Poly, DCRTPoly };


//class IL {
//	unique_ptr<ILElement<BigInteger,BigVector,ILParams>> xxx;
//};

template<typename I>
class Vector {
public:
	typedef I Integer;

	I	foo, bar;
};

template<typename V>
class MyPoly {
public:
	typedef typename V::Integer Integer;
	typedef V Vector;

	Vector x;
};

int
main(int argc, char *argv[])
{
	MyPoly<Vector<int>> p;

	p.x.foo = p.x.bar = 127;
	cout << "Hello" << endl;
	return 0;
}
