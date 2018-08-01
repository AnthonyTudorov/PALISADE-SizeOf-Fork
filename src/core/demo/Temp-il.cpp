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
class myParms {
public:
	typedef I Integer;

	Integer x;
};

template<typename I>
class myILParms : public myParms<I> {
public:
	typename myParms<I>::Integer y;
};

template<typename I>
class myILDCRTParms : public myParms<I> {
public:
	typename myParms<I>::Integer z[3];
};

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
	typedef myILParms<Integer> Parms;

	MyPoly( Parms *p ) : pptr(p) {}

	Vector x;

private:
	Parms *pptr;
};

int
main(int argc, char *argv[])
{
	myILParms<int> mp;
	MyPoly<Vector<int>> p( &mp );

	p.x.foo = p.x.bar = 127;
	cout << "Hello" << endl;
	return 0;
}
