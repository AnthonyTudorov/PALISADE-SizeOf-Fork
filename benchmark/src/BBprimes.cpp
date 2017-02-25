// run this program and redirect the output into ElementParmsHelper.h

#include <utility>
#include <iostream>
#include <sstream>
#include <string>

#define _USE_MATH_DEFINES
#include "math/backend.h"
#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;

int main( int argc, char *argv[] ) {
	stringstream	macrocode1, macrocode2;
	stringstream	parmarray;
	int parmindex = 0;

	BigBinaryInteger mod, rootUnity;
	int shifts[] = { 30, 60, 100, }; //300, 500 };

	parmarray << "shared_ptr<ILParams> parmArray[] = {" << endl;

	for( int o=8; o<=8192; o *= 2 ) {
		for( int s = 0; s < sizeof(shifts)/sizeof(shifts[0]); s++ ) {
			string pname = "parm_" + std::to_string(o) + "_" + std::to_string(shifts[s]);
			mod = FindPrimeModulus(o, shifts[s]);
			rootUnity = RootOfUnity(o, mod);

			macrocode1 << "BENCHMARK(X)->ArgName(\"" << pname << "\")->Arg(" << parmindex << "); \\" << endl;
			macrocode2 << "BENCHMARK_TEMPLATE(X,Y)->ArgName(\"" << pname << "\")->Arg(" << parmindex << "); \\" << endl;
			parmindex++;

			parmarray << pname << "," << endl;

			cout << "shared_ptr<ILParams> " << pname << "( new ILParams(" << o 
			<< ", BigBinaryInteger(\"" << mod << "\"), BigBinaryInteger(\"" << rootUnity
			<< "\")) );" << endl;
		}
	}

	cout << endl;
	cout << parmarray.str() << "};" << endl << endl;

	cout << "#define DO_PARM_BENCHMARK(X) \\" << endl;
	cout << macrocode1.str() << endl << endl;
	
	cout << "#define DO_PARM_BENCHMARK_TEMPLATE(X,Y) \\" << endl;
	cout << macrocode2.str() << endl << endl;

	return 0;
}
