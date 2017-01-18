/**
* @section DESCRIPTION
*
* This code houses all "globally"-used variables extracted from initial .tpar file
* as well as two static runtime value matrices.
*/

#include "CircuitRuntimes.h"

namespace CircuitParams {

// milliseconds multiplied by 100 (from float to int)
const int runtimesEvalAdd[6][10] = {
	// Row := log_2(ringDimension) - 9
	// Col := (int) depth / 2  [odd or even] 
	{ 21, 32, 42, 54, 64, 73, 126, 211, 290, 312 },
	{ 30, 104, 47, 57, 72, 74, 140, 272, 285, 293 },
	{ 37, 45, 55, 67, 80, 100, 197, 300, 304, 324 },
	{ 56, 65, 74, 91, 192, 207, 225, 243, 373, 354 },
	{ 89, 101, 120, 136, 246, 270, 369, 323, 505, 544 },
	{ 158, 182, 212, 239, 399, 419, 427, 477, 716, 729 }
};

// milliseconds multiplied by 100 (from float to int)
const int runtimesEvalMult[6][10] = {
	// Row := log_2(ringDimension) - 9
	// Col := (int) depth / 2  [odd or even] 
	{ 1603, 2273, 2332, 2265, 2287, 2296, 2435, 2524, 2537, 2578 },
	{ 2915, 3785, 3905, 3911, 3879, 3924, 3949, 3959, 3952, 3968 },
	{ 4917, 6631, 6677, 6741, 6715, 6838, 6822, 6927, 6945, 7109 },
	{ 9956, 14042, 14071, 14142, 14126, 14275, 14352, 14551, 14461, 14831 },
	{ 19683, 27937, 28042, 28440, 28398, 28569, 28959, 28655, 29269, 29569 },
	{ 46392, 62319, 62274, 62887, 63043, 63337, 63952, 64280, 65120, 65988 }
};

//float getEvalRuntime(string type, int depth){
//	// Get appropriate row and column
//	int row = (int)log2((double)CircuitParams::ringDimension) - 9;
//	int col = depth/ 2;
//	int value;
//	if (type == "EvalAdd" || type == "EvalNeg"){
//		// depth 0 computation
//		value = CircuitParams::runtimesEvalAdd[row][col];
//	}
//	else if (type == "EvalMult"){
//		// depth 1 computation
//		value = CircuitParams::runtimesEvalMult[row][col];
//	}
//	return (float)value *0.01;
//}

}
