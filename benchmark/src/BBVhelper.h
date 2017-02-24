// this is some helper code for benchmarking BBVs

// just #include this if you need to make random BBVs

#ifndef _BBVHELPER_H_
#define _BBVHELPER_H_

#include <utility>
#define _USE_MATH_DEFINES
#include "math/backend.h"
using namespace lbcrypto;

inline BigBinaryVector makeVector(int siz, const BigBinaryInteger& modulus) {
	BigBinaryVector vec(siz, modulus);

	return std::move(vec);
}

#endif
