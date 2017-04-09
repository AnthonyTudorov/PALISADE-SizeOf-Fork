/**
* @section DESCRIPTION
*
* This code houses all "globally"-used variables extracted from initial .tpar file 
* as well as two static runtime value matrices.
*/

#ifndef CIRCUIT_RUNTIMES
#define CIRCUIT_RUNTIMES


#include <vector>
#include <cmath>

using namespace std;

namespace CircuitParams {

	extern float getEvalRuntime(string type, int depth);

	/**
	* @brief Matrix containing all EvalAdd (depth 0) runtime values in 100*milliseconds 
	*/
	extern const int runtimesEvalAdd[6][10];
	
	/**
	* @brief Matrix containing all EvalMult (depth 1) runtime values in 100*milliseconds 
	*/
	extern const int runtimesEvalMult[6][10];
}

#endif // CIRCUIT_RUNTIMES
