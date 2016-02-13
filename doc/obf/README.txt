The following parameters need to be changed when the bit length of ring modulus q is increased (in addition to regular ILParams in the Source file).

src/obfuscate/lweconjunctionobfuscate.h (right after namespace)
//perturbation matrix parameter
const double S = 1000;

src/math/backend.h (150 should be replaced with some other value)
#if MATHBACKEND == 2
	/** Define the mapping for BigBinaryInteger */
	typedef cpu_int::BigBinaryInteger<uint32_t,150> BigBinaryInteger;

src/math/cpu_int/binint.cpp - Line 165 - "150" should be replaced with some other value
template<typename uint_type,usint BITLENGTH>
std::function<unique_ptr<BigBinaryInteger<uint_type,BITLENGTH>>()> BigBinaryInteger<uint_type,BITLENGTH>::Allocator = [=](){
	return make_unique<cpu_int::BigBinaryInteger<uint32_t,150>>();
};	
