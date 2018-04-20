#define PROFILE  //define this to enable PROFILELOG and TIC/TOC

//native libs
//#include <sys/resource.h>
#include <math.h>
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <fstream>
//created files
#include "subgaussian/inv_g.h"
#include "subgaussian/BcBD.h"

#include "utils/debug.h"

//NTL

#include <NTL/ZZ.h>
#include <NTL/vector.h>
#include <NTL/matrix.h>
#include <NTL/RR.h>

using namespace std;


int main(){

	TimeVar t1; //for TIC TOC

	double timeEval;

	long b = 3; long q = 1000; long k = (long)ceil(log2(q)/log2(b)); 
	NTL::Vec<long> output; output.SetLength(k);

	long u = 699;

	TIC(t1); //start timer for total time
	inv_g(b, q, u, k, output);
	timeEval = TOC_NS(t1);

	std::cout << "Sampling time: " << timeEval << " ns" << std::endl;
	
	NTL::RR a = NTL::RR(10.0/27); NTL::RR c = NTL::RR(19.0/27);

//test the output
long test = 0; long b_i = 1;
cout<<"********************** output = "<<endl;
	for(int i = 0; i<k; i++){
		test += output[i]*b_i;
		b_i = b_i*b;
		cout<<output[i]<<endl;
	}

cout<<"g^t * output = "<<test<<endl;
return 0;
}

// 3/23/2018: We must change the code in BcB to update the target each step!
// 4/1/2018: The code works! Now we must change the modular arithmetic to use the residues {-q/2, ... , 0, 1, ... , q/2}. (I'm not sure if this matters.)
