/*
 * Temp-smalldemo.cpp
 *
 *  Created on: Jan 4, 2018
 *      Author: gerardryan
 */

#include "palisade.h"

int
main()
{
	NativeInteger a(100);
	NativeInteger b(100);

	cout << sizeof(a) << endl;

	NativeInteger c = a.Plus(b);

//	uint64_t x;
	//unsigned __int128 y;

	a += b;

	cout << a << " " << b << " " << c;
	return 0;
}


