// this is some helper code for benchmarking BBVs

// just #include this if you need to make random BBVs

#ifndef _BBVHELPER_H_
#define _BBVHELPER_H_

#include <utility>
#define _USE_MATH_DEFINES
#include "math/backend.h"
using namespace lbcrypto;

template<typename T>
inline BigBinaryVector makeVector(shared_ptr<T> p) {
	ILVector2n::DugType dug;
	dug.SetModulus(p->GetModulus());

	BigBinaryVector v = dug.GenerateVector(p->GetCyclotomicOrder()/2);
	return std::move(v);
}

inline native64::BigBinaryVector makeNativeVector(shared_ptr<ILParams> p) {
	native64::ILVector2n::DugType dug;
	dug.SetModulus(p->GetModulus().ConvertToInt());

	uint64_t mod = p->GetModulus().ConvertToInt();
	native64::BigBinaryVector vec = dug.GenerateVector(p->GetCyclotomicOrder()/2);

	return std::move(vec);
}

#endif
