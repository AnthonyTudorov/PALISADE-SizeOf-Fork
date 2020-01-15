/*
 * @file transfrm.cpp This file contains the linear transform interface functionality.
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "math/transfrm.h"

namespace lbcrypto {

template<typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer> ChineseRemainderTransformFTT<VecType>::m_cycloOrderInverseTableByModulus;

template<typename VecType>
std::map<typename VecType::Integer, NativeInteger> ChineseRemainderTransformFTT<VecType>::m_cycloOrderInversePreconTableByModulus;

template<typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformFTT<VecType>::m_rootOfUnityReverseTableByModulus;

template<typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformFTT<VecType>::m_rootOfUnityInverseReverseTableByModulus;

template<typename VecType>
std::map<typename VecType::Integer, NativeVector> ChineseRemainderTransformFTT<VecType>::m_rootOfUnityPreconReverseTableByModulus;

template<typename VecType>
std::map<typename VecType::Integer, NativeVector> ChineseRemainderTransformFTT<VecType>::m_rootOfUnityInversePreconReverseTableByModulus;

template<typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArb<VecType>::m_cyclotomicPolyMap;

template<typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArb<VecType>::m_cyclotomicPolyReverseNTTMap;

template<typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArb<VecType>::m_cyclotomicPolyNTTMap;

template<typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType> BluesteinFFT<VecType>::m_rootOfUnityTableByModulusRoot;

template<typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType> BluesteinFFT<VecType>::m_rootOfUnityInverseTableByModulusRoot;

template<typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType> BluesteinFFT<VecType>::m_powersTableByModulusRoot;

template<typename VecType>
std::map<ModulusRootPair<typename VecType::Integer>, VecType> BluesteinFFT<VecType>::m_RBTableByModulusRootPair;

template<typename VecType>
std::map<typename VecType::Integer, ModulusRoot<typename VecType::Integer>> BluesteinFFT<VecType>::m_defaultNTTModulusRoot;

template<typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArb<VecType>::m_rootOfUnityDivisionTableByModulus;

template<typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArb<VecType>::m_rootOfUnityDivisionInverseTableByModulus;

template<typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer> ChineseRemainderTransformArb<VecType>::m_DivisionNTTModulus;

template<typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer> ChineseRemainderTransformArb<VecType>::m_DivisionNTTRootOfUnity;

template<typename VecType>
std::map<usint, usint> ChineseRemainderTransformArb<VecType>::m_nttDivisionDim;


template<typename VecType>
void NumberTheoreticTransform<VecType>::ForwardTransformIterative(const VecType& element, const VecType &rootOfUnityTable, const usint cycloOrder, VecType* result) {
	DEBUG_FLAG(false);
	usint n = cycloOrder;
	auto modulus = element.GetModulus();

#if MATHBACKEND != 6
	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(modulus);
#endif

	if( result->GetLength() != n ) {
		throw std::logic_error("Vector for NumberTheoreticTransform::ForwardTransformIterative size needs to be == cyclotomic order");
	}

	result->SetModulus(modulus);

	//reverse coefficients (bit reversal)
	usint msb = GetMSB64(n - 1);
	for (size_t i = 0; i < n; i++) {
		(*result)[i]= element[ReverseBits(i, msb)];
	}

	IntType omegaFactor;
	IntType product;
	IntType butterflyPlus;
	IntType butterflyMinus;

	/*Ring dimension factor calculates the ratio between the cyclotomic order of the root of unity table
		  that was generated originally and the cyclotomic order of the current VecType. The twiddle table
		  for lower cyclotomic orders is smaller. This trick only works for powers of two cyclotomics.*/
	float ringDimensionFactor = (float)rootOfUnityTable.GetLength() / (float)cycloOrder;
	DEBUG("rootOfUnityTable.GetLength() " << rootOfUnityTable.GetLength());
	DEBUG("cycloOrder " << cycloOrder);
	DEBUG("ringDimensionFactor " << ringDimensionFactor);
	DEBUG("n " << n);

	usint logn = log2(n);

	for (usint logm = 1; logm <= logn; logm++) {
		// calculate the i indexes into the root table one time per loop
		vector<usint> indexes(1 << (logm-1));
		for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
			indexes[i] = (i << (1+logn-logm)) * ringDimensionFactor;
		}

		for (usint j = 0; j<n; j = j + (1 << logm)) {
			for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
				const IntType& omega = rootOfUnityTable[indexes[i]];

				usint indexEven = j + i;
				usint indexOdd = indexEven + (1 << (logm-1));
				auto oddVal = (*result)[indexOdd];
				auto oddMSB = oddVal.GetMSB();

				if (oddMSB > 0) {
					if (oddMSB == 1) {
						omegaFactor = omega;
					} else {
#if MATHBACKEND != 6
						omegaFactor = omega.ModBarrettMul(oddVal,modulus,mu);
#else
						omegaFactor = omega.ModMulFast(oddVal,modulus);
#endif
					}

#if MATHBACKEND != 6
					butterflyPlus = (*result)[indexEven];
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= modulus) {
						butterflyPlus -= modulus;
					}

					butterflyMinus = (*result)[indexEven];
					if ((*result)[indexEven] < omegaFactor) {
						butterflyMinus += modulus;
					}

					butterflyMinus -= omegaFactor;

					(*result)[indexEven]= butterflyPlus;
					(*result)[indexOdd]= butterflyMinus;
#else
					(*result)[indexOdd] = (*result)[indexEven].ModSubFast(omegaFactor,modulus);
					(*result)[indexEven] = (*result)[indexEven].ModAddFast(omegaFactor,modulus);
#endif
				} else {
					(*result)[indexOdd] = (*result)[indexEven];
				}
			}
		}
	}
	return;
}

template<typename VecType>
void NumberTheoreticTransform<VecType>::ForwardTransformIterative(const VecType& element, const VecType &rootOfUnityTable,
		const NativeVector &preconRootOfUnityTable, const usint cycloOrder, VecType* result) {
	if (typeid(IntType) == typeid(NativeInteger)) {
		DEBUG_FLAG(false);
		usint n = cycloOrder;

		IntType modulus = element.GetModulus();

		if( result->GetLength() != n ) {
			throw std::logic_error("Vector for NumberTheoreticTransform::ForwardTransformIterative size needs to be == cyclotomic order");
		}

		result->SetModulus(modulus);

		//reverse coefficients (bit reversal)
		usint msb = GetMSB64(n - 1);
		for (size_t i = 0; i < n; i++) {
			(*result)[i]= element[ReverseBits(i, msb)];
		}

		IntType omegaFactor;
		IntType butterflyPlus;
		IntType butterflyMinus;

		/*Ring dimension factor calculates the ratio between the cyclotomic order of the root of unity table
			  that was generated originally and the cyclotomic order of the current VecType. The twiddle table
			  for lower cyclotomic orders is smaller. This trick only works for powers of two cyclotomics.*/
		usint ringDimensionFactor = std::round((float)rootOfUnityTable.GetLength() / (float)cycloOrder);

		DEBUG("rootOfUnityTable.GetLength() " << rootOfUnityTable.GetLength());
		DEBUG("cycloOrder " << cycloOrder);
		//DEBUG("ringDimensionFactor " << ringDimensionFactor);
		DEBUG("n " << n);

		usint logn = log2(n);

		if (modulus.GetMSB() < MAX_MODULUS_SIZE + 1) {
			for (usint logm = 1; logm <= logn; logm++) {

				// calculate the i indexes into the root table one time per loop
				vector<usint> indexes(1 << (logm-1));
				if (ringDimensionFactor == 1) {
					for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
						indexes[i] = (i << (1+logn-logm));
					}
				} else {
					for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
						indexes[i] = (i << (1+logn-logm)) * ringDimensionFactor;
					}
				}

				for (usint j = 0; j<n; j = j + (1 << logm)) {
					for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
						usint x = indexes[i];

						IntType omega = rootOfUnityTable[x];
						IntType preconOmega = preconRootOfUnityTable[x];

						usint indexEven = j + i;
						usint indexOdd = indexEven + (1 << (logm-1));

						IntType oddVal = (*result)[indexOdd];

						if (oddVal != IntType(0)) {
							if (oddVal == IntType(1)) {
								omegaFactor = omega;
							} else {
								omegaFactor = oddVal.ModMulPreconOptimized(omega,modulus,preconOmega);
							}

							butterflyPlus = (*result)[indexEven];
							butterflyPlus += omegaFactor;
							if (butterflyPlus >= modulus) {
								butterflyPlus -= modulus;
							}

							butterflyMinus = (*result)[indexEven];
							if (butterflyMinus < omegaFactor) {
								butterflyMinus += modulus;
							}
							butterflyMinus -= omegaFactor;

							(*result)[indexEven]= butterflyPlus;
							(*result)[indexOdd]= butterflyMinus;
						} else {
							(*result)[indexOdd] = (*result)[indexEven];
						}
					}
				}
			}
		} else {
			for (usint logm = 1; logm <= logn; logm++) {

				// calculate the i indexes into the root table one time per loop
				vector<usint> indexes(1 << (logm-1));
				if (ringDimensionFactor == 1) {
					for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
						indexes[i] = (i << (1+logn-logm));
					}
				} else {
					for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
						indexes[i] = (i << (1+logn-logm)) * ringDimensionFactor;
					}
				}

				for (usint j = 0; j<n; j = j + (1 << logm)) {
					for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
						usint x = indexes[i];

						IntType omega = rootOfUnityTable[x];

						usint indexEven = j + i;
						usint indexOdd = indexEven + (1 << (logm-1));
						IntType oddVal = (*result)[indexOdd];

						if (oddVal != IntType(0)) {
							if (oddVal == IntType(1)) {
								omegaFactor = omega;
							} else {
								omegaFactor = oddVal.ModMulFast(omega,modulus);
							}

							butterflyPlus = (*result)[indexEven];
							butterflyPlus += omegaFactor;
							if (butterflyPlus >= modulus) {
								butterflyPlus -= modulus;
							}

							butterflyMinus = (*result)[indexEven];
							if ((*result)[indexEven] < omegaFactor) {
								butterflyMinus += modulus;
							}
							butterflyMinus -= omegaFactor;

							(*result)[indexEven]= butterflyPlus;
							(*result)[indexOdd]= butterflyMinus;
						} else {
							(*result)[indexOdd] = (*result)[indexEven];
						}
					}
				}
			}
		}
	} else {
		PALISADE_THROW(math_error, "This NTT method only works with NativeInteger");
	}
	return;
}

template<typename VecType>
void NumberTheoreticTransform<VecType>::ForwardTransformIterativeCT(const VecType& element,
		const VecType &rootOfUnityTable, const usint cycloOrder, VecType* result) {

	usint n = cycloOrder;
	if( result->GetLength() != n ) {
		throw std::logic_error("Vector for NumberTheoreticTransform::ForwardTransformIterative size needs to be == cyclotomic order");
	}

	IntType modulus = element.GetModulus();
#if MATHBACKEND != 6
	IntType mu = ComputeMu<IntType>(modulus); //Precompute the Barrett mu parameter
#endif

	result->SetModulus(modulus);

	IntType hiVal, loVal, omega, omegaFactor;
	usint i, m, j1, j2, indexOmega, indexHi, indexLo;

	for (i = 0; i < n; i++) {
		(*result)[i]= element[i];
	}

	usint t = n;
	usint logt1 = GetMSB64(n);
	for (m = 1; m < n; m = m << 1) {
		t >>= 1;
		logt1 -= 1;
		for (i = 0; i < m; ++i) {
			j1 = i << logt1;
			j2 = j1 + t;
			indexOmega = m + i;
			omega = rootOfUnityTable[indexOmega];
			for (indexLo = j1; indexLo < j2; ++indexLo) {
				indexHi = indexLo + t;

				hiVal = (*result)[indexHi];
				auto hiMSB = hiVal.GetMSB();
				if (hiMSB > 0) {
					if (hiMSB == 1)  {
						omegaFactor = omega;
					} else {
#if MATHBACKEND != 6
						omegaFactor = omega.ModBarrettMul(hiVal, modulus, mu);
#else
						omegaFactor = omega.ModMulFast(hiVal, modulus);
#endif
					}

#if MATHBACKEND != 6
					loVal = (*result)[indexLo];
					hiVal = loVal;
					hiVal += omegaFactor;
					if (hiVal >= modulus) {
						hiVal -= modulus;
					}

					if (loVal < omegaFactor) {
						loVal += modulus;
					}
					loVal -= omegaFactor;

					(*result)[indexLo] = hiVal;
					(*result)[indexHi] = loVal;
#else
					(*result)[indexHi] = (*result)[indexLo].ModSubFast(omegaFactor, modulus);
					(*result)[indexLo] = (*result)[indexLo].ModAddFast(omegaFactor, modulus);
#endif
				} else {
					(*result)[indexHi] = (*result)[indexLo];
				}
			}
		}
	}
	return;
}

template<typename VecType>
void NumberTheoreticTransform<VecType>::ForwardTransformIterativeCT(const VecType& element, const VecType &rootOfUnityTable,
		const NativeVector &preconRootOfUnityTable, const usint cycloOrder, VecType* result) {
	if (typeid(IntType) == typeid(NativeInteger)) {

		usint n = cycloOrder;
		if(result->GetLength() != n) {
			throw std::logic_error("Vector for NumberTheoreticTransform::ForwardTransformIterative size needs to be == cyclotomic order");
		}

		IntType modulus = element.GetModulus();

		result->SetModulus(modulus);

		IntType loVal, hiVal, omega, omegaFactor, zero(0), one(1);
		NativeInteger preconOmega;
		usint i, m, j1, j2, indexLo, indexHi, indexOmega;

		for (i = 0; i < n; ++i) {
			(*result)[i]= element[i];
		}

		usint t = n;
		usint logt1 = GetMSB64(n);
		if (modulus.GetMSB() < MAX_MODULUS_SIZE + 1) {
			for (m = 1; m < n; m <<= 1) {
				t >>= 1;
				logt1 -= 1;
				for (i = 0; i < m; ++i) {
					j1 = i << logt1;
					j2 = j1 + t;
					indexOmega = m + i;
					omega = rootOfUnityTable[indexOmega];
					NativeInteger preconOmega = preconRootOfUnityTable[indexOmega];

					for (indexLo = j1; indexLo < j2; ++indexLo) {
						indexHi = indexLo + t;
						hiVal = (*result)[indexHi];

						if (hiVal != zero) {
							if (hiVal == one) {
								omegaFactor = omega;
							} else {
								omegaFactor = hiVal.ModMulPreconOptimized(omega, modulus, preconOmega);
							}
							loVal = (*result)[indexLo];

							hiVal = loVal;
							hiVal += omegaFactor;
							if (hiVal >= modulus) {
								hiVal -= modulus;
							}

							if (loVal < omegaFactor) {
								loVal += modulus;
							}
							loVal -= omegaFactor;

							(*result)[indexLo]= hiVal;
							(*result)[indexHi]= loVal;
						} else {
							(*result)[indexHi] = (*result)[indexLo];
						}
					}
				}
			}
		} else {
			for (m = 1; m < n; m = m << 1) {
				t >>= 1;
				logt1 -= 1;
				for (i = 0; i < m; ++i) {
					j1 = (i << logt1);
					j2 = j1 + t;
					indexOmega = m + i;
					omega = rootOfUnityTable[indexOmega];
					for (indexLo = j1; indexLo < j2; ++indexLo) {
						indexHi = indexLo + t;
						hiVal = (*result)[indexHi];

						if (hiVal != zero) {
							if (hiVal == one) {
								omegaFactor = omega;
							} else {
								omegaFactor = omega.ModMulFast(hiVal, modulus);
							}

							loVal = (*result)[indexLo];
							hiVal = loVal;
							hiVal += omegaFactor;
							if (hiVal >= modulus) {
								hiVal -= modulus;
							}

							if (loVal < omegaFactor) {
								loVal += modulus;
							}
							loVal -= omegaFactor;

							(*result)[indexLo]= hiVal;
							(*result)[indexHi]= loVal;
						} else {
							(*result)[indexHi] = (*result)[indexLo];
						}
					}
				}
			}
		}
	} else {
		PALISADE_THROW(math_error, "This NTT method only works with NativeInteger");
	}
	return;
}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
template<typename VecType>
void NumberTheoreticTransform<VecType>::InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable,
		const usint cycloOrder, VecType *result) {

	result->SetModulus(element.GetModulus());

	NumberTheoreticTransform<VecType>::ForwardTransformIterative(element, rootOfUnityInverseTable, cycloOrder, result);

	//TODO:: note this could be stored
	*result *= (IntType(cycloOrder).ModInverse(element.GetModulus()));
	return;
}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
template<typename VecType>
void NumberTheoreticTransform<VecType>::InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable,
		const NativeVector& preconRootOfUnityInverseTable, const usint cycloOrder, VecType *result) {
	if (typeid(IntType) == typeid(NativeInteger)) {

		result->SetModulus(element.GetModulus());

		NumberTheoreticTransform<VecType>::ForwardTransformIterative(element, rootOfUnityInverseTable,
				preconRootOfUnityInverseTable, cycloOrder, result);

		//TODO:: note this could be stored
		*result *= (IntType(cycloOrder).ModInverse(element.GetModulus()));
	} else {
		PALISADE_THROW(math_error, "This NTT method only works with NativeInteger");
	}

	return;
}

template<typename VecType>
void NumberTheoreticTransform<VecType>::InverseTransformIterativeGS(const VecType& element, const VecType& rootOfUnityInverseTable,
		const IntType& cycloOrderInv, const usint cycloOrder, VecType *result) {

	usint n = cycloOrder;
	if(result->GetLength() != n) {
		throw std::logic_error("Vector for NumberTheoreticTransform::ForwardTransformIterative size needs to be == cyclotomic order");
	}

	IntType modulus = element.GetModulus();
#if MATHBACKEND != 6
	IntType mu = ComputeMu<IntType>(modulus); //Precompute the Barrett mu parameter
#endif

	result->SetModulus(modulus);

	IntType loVal, hiVal, omega, butterflyMinus;
	usint i, m, j1, h, j2, indexOmega, indexLo, indexHi;

	for (i = 0; i < n; i++) {
		(*result)[i]= element[i];
	}

	usint t = 1;
	for (m = n; m > 1; m = m >> 1) {
		j1 = 0;
		h = m >> 1;
		for (usint i = 0; i < h; ++i) {
			j2 = j1 + t;
			indexOmega = h + i;
			omega = rootOfUnityInverseTable[indexOmega];
			for (indexLo = j1; indexLo < j2; ++indexLo) {
				indexHi = indexLo + t;

				loVal = (*result)[indexLo];
				hiVal = (*result)[indexHi];

#if MATHBACKEND != 6
				butterflyMinus = loVal;
				if (butterflyMinus < hiVal) {
					butterflyMinus += modulus;
				}
				butterflyMinus -= hiVal;

				loVal += hiVal;
				if (loVal >= modulus) {
					loVal -= modulus;
				}
#else
				butterflyMinus = loVal.ModSubFast(hiVal,modulus);
				loVal = loVal.ModAddFast(hiVal, modulus);
#endif

				auto bmMSB = butterflyMinus.GetMSB();
				if (bmMSB > 0) {
					if (bmMSB == 1) {
						butterflyMinus = omega;
					} else {
#if MATHBACKEND != 6
						butterflyMinus.ModBarrettMulEq(omega, modulus, mu);
#else
						butterflyMinus.ModMulFastEq(omega, modulus);
#endif
					}
				}

				(*result)[indexLo]= loVal;
				(*result)[indexHi]= butterflyMinus;
			}
			j1 += (t << 1);
		}
		t <<= 1;
	}
	*result *= cycloOrderInv;
	return;
}

template<typename VecType>
void NumberTheoreticTransform<VecType>::InverseTransformIterativeGS(const VecType& element, const VecType& rootOfUnityInverseTable,
		const NativeVector& preconRootOfUnityInverseTable, const IntType& cycloOrderInv, const IntType& preconCycloOrderInv, const usint cycloOrder, VecType *result) {
	if (typeid(IntType) == typeid(NativeInteger)) {

		usint n = cycloOrder;
		if( result->GetLength() != n ) {
			throw std::logic_error("Vector for NumberTheoreticTransform::ForwardTransformIterative size needs to be == cyclotomic order");
		}

		IntType modulus = element.GetModulus();

		result->SetModulus(modulus);

		IntType loVal, hiVal, omega, butterflyMinus, zero(0), one(1);
		NativeInteger preconOmega;
		usint i, m, j1, h, j2, indexOmega, indexLo, indexHi;

		for (i = 0; i < n; i++) {
			(*result)[i]= element[i];
		}

		usint t = 1;
		if (modulus.GetMSB() < MAX_MODULUS_SIZE + 1) {
			for (m = n; m > 1; m >>= 1) {
				j1 = 0;
				h = (m >> 1);
				for (i = 0; i < h; ++i) {
					j2 = j1 + t;
					indexOmega = h + i;
					omega = rootOfUnityInverseTable[indexOmega];
					preconOmega = preconRootOfUnityInverseTable[indexOmega];

					for (indexLo = j1; indexLo < j2; ++indexLo) {
						indexHi = indexLo + t;

						loVal = (*result)[indexLo];
						hiVal = (*result)[indexHi];

						butterflyMinus = loVal;
						if (butterflyMinus < hiVal) {
							butterflyMinus += modulus;
						}
						butterflyMinus -= hiVal;

						if (butterflyMinus != zero) {
							if (butterflyMinus == one) {
								butterflyMinus = omega;
							} else {
								butterflyMinus.ModMulPreconOptimizedEq(omega, modulus, preconOmega);
							}
						}

						loVal += hiVal;
						if (loVal >= modulus) {
							loVal -= modulus;
						}

						(*result)[indexLo] = loVal;
						(*result)[indexHi] = butterflyMinus;
					}
					j1 += (t << 1);
				}
				t <<= 1;
			}
			for (i = 0; i < n; i++) {
				(*result)[i].ModMulPreconOptimizedEq(cycloOrderInv, modulus, preconCycloOrderInv);
			}
		} else {
			for (m = n; m > 1; m >>= 1) {
				j1 = 0;
				h = m >> 1;
				for (i = 0; i < h; ++i) {
					j2 = j1 + t;
					indexOmega = h + i;
					omega = rootOfUnityInverseTable[indexOmega];
					for (indexLo = j1; indexLo < j2; ++indexLo) {
						indexHi = indexLo + t;

						loVal = (*result)[indexLo];
						hiVal = (*result)[indexHi];

						butterflyMinus = loVal;
						if (butterflyMinus < hiVal) {
							butterflyMinus += modulus;
						}
						butterflyMinus -= hiVal;

						if (butterflyMinus != zero) {
							if (butterflyMinus == one) {
								butterflyMinus = omega;
							} else {
								butterflyMinus.ModMulFastEq(omega, modulus);
							}
						}

						loVal += hiVal;
						if (loVal >= modulus) {
							loVal -= modulus;
						}

						(*result)[indexLo]= loVal;
						(*result)[indexHi]= butterflyMinus;
					}
					j1 += (t << 1);
				}
				t <<= 1;
			}
			*result *= cycloOrderInv;
		}
	} else {
		PALISADE_THROW(math_error, "This NTT method only works with NativeInteger");
	}
	return;
}

template<typename VecType>
void ChineseRemainderTransformFTT<VecType>::ForwardTransform(const VecType& element, const IntType& rootOfUnity,
		const usint CycloOrder, VecType *result) {

	if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0)) {
		*result = element;
		return;
	}

	if (!IsPowerOfTwo(CycloOrder)) {
		throw std::logic_error("CyclotomicOrder for ChineseRemainderTransformFTT::ForwardTransform is not a power of two");
	}

	usint CycloOrderHf = CycloOrder / 2;
	if(result->GetLength() != CycloOrderHf) {
		throw std::logic_error("Vector for ChineseRemainderTransformFTT::ForwardTransform size must be == CyclotomicOrder/2");
	}

	IntType modulus = element.GetModulus();

	auto mapSearch = m_rootOfUnityReverseTableByModulus.find(modulus);
	if(mapSearch == m_rootOfUnityReverseTableByModulus.end() || mapSearch->second.GetLength() != CycloOrderHf) {
		PreCompute(rootOfUnity, CycloOrder, modulus);
	}

	if (typeid(IntType) == typeid(NativeInteger)) {
		NumberTheoreticTransform<VecType>::ForwardTransformIterativeCT(element,
				m_rootOfUnityReverseTableByModulus[modulus],
				m_rootOfUnityPreconReverseTableByModulus[modulus], CycloOrderHf, result);
	} else {
		NumberTheoreticTransform<VecType>::ForwardTransformIterativeCT(element,
				m_rootOfUnityReverseTableByModulus[modulus], CycloOrderHf, result);
	}

	return;
}

template<typename VecType>
void ChineseRemainderTransformFTT<VecType>::InverseTransform(const VecType& element, const IntType& rootOfUnity,
		const usint CycloOrder, VecType *result) {

	if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0)) {
		*result = element;
		return;
	}

	if (!IsPowerOfTwo(CycloOrder)) {
		throw std::logic_error("CyclotomicOrder for ChineseRemainderTransformFTT::InverseTransform is not a power of two");
	}

	usint CycloOrderHf = CycloOrder / 2;
	if(result->GetLength() != CycloOrderHf) {
		throw std::logic_error("Vector for ChineseRemainderTransformFTT::InverseTransform size must be == CyclotomicOrder/2");
	}

	IntType modulus = element.GetModulus();

	auto mapSearch = m_rootOfUnityReverseTableByModulus.find(modulus);
	if(mapSearch == m_rootOfUnityReverseTableByModulus.end() || mapSearch->second.GetLength() != CycloOrderHf) {
		PreCompute(rootOfUnity, CycloOrder, modulus);
	}

	if (typeid(IntType) == typeid(NativeInteger)) {
		NumberTheoreticTransform<VecType>::InverseTransformIterativeGS(element,
				m_rootOfUnityInverseReverseTableByModulus[modulus],
				m_rootOfUnityInversePreconReverseTableByModulus[modulus],
				m_cycloOrderInverseTableByModulus[modulus],
				m_cycloOrderInversePreconTableByModulus[modulus], CycloOrderHf, result);
	} else {
		NumberTheoreticTransform<VecType>::InverseTransformIterativeGS(element,
				m_rootOfUnityInverseReverseTableByModulus[modulus],
				m_cycloOrderInverseTableByModulus[modulus], CycloOrderHf, result);
	}

	return;
}

template<typename VecType>
void ChineseRemainderTransformFTT<VecType>::PreCompute(const IntType& rootOfUnity, const usint CycloOrder, const IntType &modulus) {

	usint CycloOrderHf = CycloOrder / 2;

	auto mapSearch = m_rootOfUnityReverseTableByModulus.find(modulus);
	if(mapSearch == m_rootOfUnityReverseTableByModulus.end() ||
			mapSearch->second.GetLength() != CycloOrderHf) {

		#pragma omp critical
		{
			IntType x(1), xinv(1);
			usint msb = GetMSB64(CycloOrderHf - 1);
			IntType mu = ComputeMu<IntType>(modulus);
			VecType Table(CycloOrderHf, modulus);
			VecType TableI(CycloOrderHf, modulus);
			IntType rootOfUnityInverse = rootOfUnity.ModInverse(modulus);
			usint iinv;
			for (usint i = 0; i < CycloOrderHf; i++) {
				iinv = ReverseBits(i, msb);
				Table[iinv] = x;
				TableI[iinv]= xinv;
				x.ModBarrettMulInPlace(rootOfUnity, modulus, mu);
				xinv.ModBarrettMulInPlace(rootOfUnityInverse, modulus, mu);
			}
			m_rootOfUnityReverseTableByModulus[modulus] = std::move(Table);
			m_rootOfUnityInverseReverseTableByModulus[modulus] = std::move(TableI);

			IntType cycloOrderHfInv(IntType(CycloOrderHf).ModInverse(modulus));
			m_cycloOrderInverseTableByModulus[modulus] = std::move(cycloOrderHfInv);

			if (typeid(IntType) == typeid(NativeInteger)) {
				NativeInteger nativeModulus = modulus.ConvertToInt();
				NativeVector preconTable(CycloOrderHf,nativeModulus);
				NativeVector preconTableI(CycloOrderHf,nativeModulus);
				NativeInteger preconCycloOrderInv;

				if(modulus.GetMSB() < MAX_MODULUS_SIZE + 1){
					for (usint i = 0; i < CycloOrderHf; i++) {
						preconTable[i] = NativeInteger(m_rootOfUnityReverseTableByModulus[modulus].operator[](i).ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
						preconTableI[i] = NativeInteger(m_rootOfUnityInverseReverseTableByModulus[modulus].operator[](i).ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
					}
					preconCycloOrderInv = NativeInteger(cycloOrderHfInv.ConvertToInt()).PrepModMulPreconOptimized(nativeModulus);
				} else {
					for (usint i = 0; i < CycloOrderHf; i++) {
						preconTable[i] = 0;
						preconTableI[i] = 0;
					}
					preconCycloOrderInv = 0;
				}

				m_rootOfUnityPreconReverseTableByModulus[modulus] = std::move(preconTable);
				m_rootOfUnityInversePreconReverseTableByModulus[modulus] = std::move(preconTableI);
				m_cycloOrderInversePreconTableByModulus[modulus] = std::move(preconCycloOrderInv);
			}
		}
	}
}

template<typename VecType>
void ChineseRemainderTransformFTT<VecType>::PreCompute(std::vector<IntType> &rootOfUnity, const usint CycloOrder, std::vector<IntType> &moduliiChain) {

	usint numOfRootU = rootOfUnity.size();
	usint numModulii = moduliiChain.size();

	if (numOfRootU != numModulii) {
		throw std::logic_error("size of root of unity and size of moduli chain not of same size");
	}

	for (usint i = 0; i < numOfRootU; ++i) {
		IntType currentRoot(rootOfUnity[i]);
		IntType currentMod(moduliiChain[i]);
		PreCompute(currentRoot, CycloOrder, currentMod);
	}
}

template<typename VecType>
void ChineseRemainderTransformFTT<VecType>::Reset() {
	m_cycloOrderInverseTableByModulus.clear();
	m_cycloOrderInversePreconTableByModulus.clear();
	m_rootOfUnityReverseTableByModulus.clear();
	m_rootOfUnityInverseReverseTableByModulus.clear();
	m_rootOfUnityPreconReverseTableByModulus.clear();
	m_rootOfUnityInversePreconReverseTableByModulus.clear();
}
	


template<typename VecType>
void BluesteinFFT<VecType>::PreComputeDefaultNTTModulusRoot(usint cycloOrder, const IntType &modulus) {
	usint nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));
	const auto nttModulus = FirstPrime<IntType>(log2(nttDim) + 2 * modulus.GetMSB(), nttDim);
	const auto nttRoot = RootOfUnity(nttDim, nttModulus);
	const ModulusRoot<IntType> nttModulusRoot = {nttModulus, nttRoot};
	m_defaultNTTModulusRoot[modulus] = nttModulusRoot;

	PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
}

template<typename VecType>
void BluesteinFFT<VecType>::PreComputeRootTableForNTT(usint cyclotoOrder, const ModulusRoot<IntType> &nttModulusRoot) {
	usint nttDim = pow(2, ceil(log2(2 * cyclotoOrder - 1)));
	const auto &nttModulus = nttModulusRoot.first;
	const auto &nttRoot = nttModulusRoot.second;

	IntType root(nttRoot);

	auto rootInv = root.ModInverse(nttModulus);

	VecType rootTable(nttDim / 2, nttModulus);
	VecType rootTableInverse(nttDim / 2, nttModulus);

	IntType x(1);
	for (usint i = 0; i<nttDim / 2; i++) {
		rootTable[i]= x;
		x = x.ModMul(root, nttModulus);
	}

	x = 1;
	for (usint i = 0; i<nttDim / 2; i++) {
		rootTableInverse[i]= x;
		x = x.ModMul(rootInv, nttModulus);
	}

	m_rootOfUnityTableByModulusRoot[nttModulusRoot] = rootTable;
	m_rootOfUnityInverseTableByModulusRoot[nttModulusRoot] = rootTableInverse;
}

template<typename VecType>
void BluesteinFFT<VecType>::PreComputePowers(usint cycloOrder, const ModulusRoot<IntType> &modulusRoot) {
	const auto &modulus = modulusRoot.first;
	const auto &root = modulusRoot.second;

	VecType powers(cycloOrder, modulus);
	powers[0]= 1;
	for (usint i = 1; i <cycloOrder; i++) {
		auto iSqr = (i*i) % (2 * cycloOrder);
		auto val = root.ModExp(IntType(iSqr), modulus);
		powers[i]= val;
	}
	m_powersTableByModulusRoot[modulusRoot] = std::move(powers);
}

template<typename VecType>
void BluesteinFFT<VecType>::PreComputeRBTable(usint cycloOrder, const ModulusRootPair<IntType> &modulusRootPair) {
	const auto &modulusRoot = modulusRootPair.first;
	const auto &modulus = modulusRoot.first;
	const auto &root = modulusRoot.second;
	const auto rootInv = root.ModInverse(modulus);

	const auto &nttModulusRoot = modulusRootPair.second;
	const auto &nttModulus = nttModulusRoot.first;
	// const auto &nttRoot = nttModulusRoot.second;
	const auto &rootTable = m_rootOfUnityTableByModulusRoot[nttModulusRoot]; //assumes rootTable is precomputed
	usint nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));

	VecType b(2 * cycloOrder - 1, modulus);
	b[cycloOrder - 1] = 1;
	for (usint i = 1; i < cycloOrder; i++) {
		auto iSqr = (i*i) % (2 * cycloOrder);
		auto val = rootInv.ModExp(IntType(iSqr), modulus);
		b[cycloOrder - 1 + i]= val;
		b[cycloOrder - 1 - i]= val;
	}

	auto Rb = PadZeros(b, nttDim);
	Rb.SetModulus(nttModulus);

	VecType RB(nttDim);
	NumberTheoreticTransform<VecType>::ForwardTransformIterative(Rb, rootTable, nttDim, &RB);
	m_RBTableByModulusRootPair[modulusRootPair] = std::move(RB);

}

template<typename VecType>
VecType BluesteinFFT<VecType>::ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder) {
	const auto &modulus = element.GetModulus();
	const auto &nttModulusRoot = m_defaultNTTModulusRoot[modulus];

	return ForwardTransform(element, root, cycloOrder, nttModulusRoot);
}

template<typename VecType>
VecType BluesteinFFT<VecType>::ForwardTransform(const VecType& element, const IntType& root,
		const usint cycloOrder, const ModulusRoot<IntType>& nttModulusRoot) {
	if (element.GetLength() != cycloOrder) {
		throw std::runtime_error("expected size of element vector should be equal to cyclotomic order");
	}

	const auto &modulus = element.GetModulus();
	const ModulusRoot<IntType> modulusRoot = {modulus, root};
	const VecType &powers = m_powersTableByModulusRoot[modulusRoot];

	const auto &nttModulus = nttModulusRoot.first;
	const auto &rootTable = m_rootOfUnityTableByModulusRoot[nttModulusRoot]; //assumes rootTable is precomputed
	const auto &rootTableInverse = m_rootOfUnityInverseTableByModulusRoot[nttModulusRoot]; //assumes rootTableInverse is precomputed

	VecType x(element*powers);

	usint nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));
	auto Ra = PadZeros(x, nttDim);
	Ra.SetModulus(nttModulus);
	VecType RA(nttDim);
	NumberTheoreticTransform<VecType>::ForwardTransformIterative(Ra, rootTable, nttDim, &RA);

	const ModulusRootPair<IntType> modulusRootPair = {modulusRoot, nttModulusRoot};
	const auto &RB = m_RBTableByModulusRootPair[modulusRootPair];

	auto RC = RA*RB;
	VecType Rc(nttDim);
	NumberTheoreticTransform<VecType>::InverseTransformIterative(RC, rootTableInverse, nttDim, &Rc);
	auto resizeRc = Resize(Rc, cycloOrder - 1, 2 * (cycloOrder - 1));
	resizeRc.SetModulus(modulus);

	auto result = resizeRc*powers;

	return result;
}

template<typename VecType>
VecType BluesteinFFT<VecType>::PadZeros(const VecType &a, const usint finalSize) {
	usint s = a.GetLength();
	VecType result(finalSize, a.GetModulus());

	for (usint i = 0; i < s; i++) {
		result[i]= a[i];
	}

	for (usint i = a.GetLength(); i < finalSize; i++) {
		result[i]= IntType(0);
	}

	return result;
}

template<typename VecType>
VecType BluesteinFFT<VecType>::Resize(const VecType &a, usint  lo, usint hi) {
	VecType result(hi - lo + 1, a.GetModulus());

	for (usint i = lo, j = 0; i <= hi; i++, j++) {
		result[j]= a[i];
	}

	return result;
}

template<typename VecType>
void BluesteinFFT<VecType>::Reset() {
	m_rootOfUnityTableByModulusRoot.clear();
	m_rootOfUnityInverseTableByModulusRoot.clear();
	m_powersTableByModulusRoot.clear();
	m_RBTableByModulusRootPair.clear();
	m_defaultNTTModulusRoot.clear();
}

template<typename VecType>
void ChineseRemainderTransformArb<VecType>::SetCylotomicPolynomial(const VecType &poly, const IntType &mod) {
	m_cyclotomicPolyMap[mod] = poly;
}

template<typename VecType>
void ChineseRemainderTransformArb<VecType>::PreCompute(const usint cyclotoOrder, const IntType &modulus) {
	BluesteinFFT<VecType>::PreComputeDefaultNTTModulusRoot(cyclotoOrder, modulus);
}

template<typename VecType>
void ChineseRemainderTransformArb<VecType>::SetPreComputedNTTModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttModulus, const IntType &nttRoot) {
	const ModulusRoot<IntType> nttModulusRoot = { nttModulus, nttRoot };
	BluesteinFFT<VecType>::PreComputeRootTableForNTT(cyclotoOrder, nttModulusRoot);
}

template<typename VecType>
void ChineseRemainderTransformArb<VecType>::SetPreComputedNTTDivisionModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod,
	const IntType &nttRootBig) {
	DEBUG_FLAG(false);

	usint n = GetTotient(cyclotoOrder);
	DEBUG("GetTotient("<<cyclotoOrder<<")= "<<n);

	usint power = cyclotoOrder - n;
	m_nttDivisionDim[cyclotoOrder] = 2 * std::pow(2, ceil(log2(power)));

	usint nttDimBig = std::pow(2, ceil(log2(2 * cyclotoOrder - 1)));

	// Computes the root of unity for the division NTT based on the root of unity for regular NTT
	IntType nttRoot = nttRootBig.ModExp(IntType(nttDimBig / m_nttDivisionDim[cyclotoOrder]), nttMod);

	m_DivisionNTTModulus[modulus] = nttMod;
	m_DivisionNTTRootOfUnity[modulus] = nttRoot;
	//part0 setting of rootTable and inverse rootTable
	usint nttDim = m_nttDivisionDim[cyclotoOrder];
	IntType root(nttRoot);
	auto rootInv = root.ModInverse(nttMod);

	VecType rootTable(nttDim / 2, nttMod);
	VecType rootTableInverse(nttDim / 2, nttMod);

	IntType x(1);
	for (usint i = 0; i < nttDim / 2; i++) {
		rootTable[i]= x;
		x = x.ModMul(root, nttMod);
	}

	x = 1;
	for (usint i = 0; i < nttDim / 2; i++) {
		rootTableInverse[i]= x;
		x = x.ModMul(rootInv, nttMod);
	}

	m_rootOfUnityDivisionTableByModulus[nttMod] = rootTable;
	m_rootOfUnityDivisionInverseTableByModulus[nttMod] = rootTableInverse;

	//end of part0
	//part1
	const auto &RevCPM = InversePolyMod(m_cyclotomicPolyMap[modulus], modulus, power);
	auto RevCPMPadded = BluesteinFFT<VecType>::PadZeros(RevCPM, nttDim);
	RevCPMPadded.SetModulus(nttMod);
	//end of part1

	VecType RA(nttDim);
	NumberTheoreticTransform<VecType>::ForwardTransformIterative(RevCPMPadded, rootTable, nttDim, &RA);
	m_cyclotomicPolyReverseNTTMap[modulus] = std::move(RA);

	const auto &cycloPoly = m_cyclotomicPolyMap[modulus];

	VecType QForwardTransform(nttDim, nttMod);
	for (usint i = 0; i < cycloPoly.GetLength(); i++) {
		QForwardTransform[i]= cycloPoly[i];
	}

	VecType QFwdResult(nttDim);
	NumberTheoreticTransform<VecType>::ForwardTransformIterative(QForwardTransform, rootTable, nttDim, &QFwdResult);

	m_cyclotomicPolyNTTMap[modulus] = std::move(QFwdResult);
}

template<typename VecType>
VecType ChineseRemainderTransformArb<VecType>::InversePolyMod(const VecType &cycloPoly, const IntType &modulus, usint power) {

	VecType result(power, modulus);
	usint r = ceil(log2(power));
	VecType h(1, modulus);//h is a unit polynomial
	h[0]= 1;

	//Precompute the Barrett mu parameter
	IntType mu = ComputeMu<IntType>(modulus);

	for (usint i = 0; i < r; i++) {
		usint qDegree = std::pow(2, i + 1);
		VecType q(qDegree + 1, modulus);//q = x^(2^i+1)
		q[qDegree]= 1;
		auto hSquare = PolynomialMultiplication(h, h);

		auto a = h * IntType(2);
		auto b = PolynomialMultiplication(hSquare, cycloPoly);
		//b = 2h - gh^2
		for (usint j = 0; j < b.GetLength(); j++) {
			if (j < a.GetLength()) {
				b[j]= a[j].ModBarrettSub(b[j], modulus, mu);
			} else {
				b[j]= modulus.ModBarrettSub(b[j], modulus, mu);
			}
		}
		h = PolyMod(b, q, modulus);

	}
	//take modulo x^power
	for (usint i = 0; i < power; i++) {
		result[i]= h[i];
	}

	return result;
}

template<typename VecType>
VecType ChineseRemainderTransformArb<VecType>::ForwardTransform(const VecType& element, const IntType& root, const IntType& nttModulus,
	const IntType& nttRoot, const usint cycloOrder) {
	usint phim = GetTotient(cycloOrder);
	if (element.GetLength() != phim) {
		throw std::runtime_error("element size should be equal to phim");
	}

	const auto &modulus = element.GetModulus();
	const ModulusRoot<IntType> modulusRoot = { modulus, root };

	const ModulusRoot<IntType> nttModulusRoot = { nttModulus, nttRoot };
	const ModulusRootPair<IntType> modulusRootPair = {  modulusRoot, nttModulusRoot };

#pragma omp critical
	{
		if (BluesteinFFT<VecType>::m_rootOfUnityTableByModulusRoot[nttModulusRoot].GetLength() == 0) {
			BluesteinFFT<VecType>::PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
		}

		if (BluesteinFFT<VecType>::m_powersTableByModulusRoot[modulusRoot].GetLength() == 0) {
			BluesteinFFT<VecType>::PreComputePowers(cycloOrder, modulusRoot);
		}

		if(BluesteinFFT<VecType>::m_RBTableByModulusRootPair[modulusRootPair].GetLength() == 0){
			BluesteinFFT<VecType>::PreComputeRBTable(cycloOrder, modulusRootPair);
		}
	}

	VecType inputToBluestein = Pad(element, cycloOrder, true);
	auto outputBluestein = BluesteinFFT<VecType>::ForwardTransform(inputToBluestein, root, cycloOrder, nttModulusRoot);
	VecType output = Drop(outputBluestein, cycloOrder, true, nttModulus, nttRoot);

	return output;

}

template<typename VecType>
VecType ChineseRemainderTransformArb<VecType>::InverseTransform(const VecType& element, const IntType& root,
		const IntType& nttModulus, const IntType& nttRoot, const usint cycloOrder) {
	usint phim = GetTotient(cycloOrder);
	if (element.GetLength() != phim) {
		throw std::runtime_error("element size should be equal to phim");
	}

	const auto &modulus = element.GetModulus();
	auto rootInverse(root.ModInverse(modulus));
	const ModulusRoot<IntType> modulusRootInverse = { modulus, rootInverse };

	const ModulusRoot<IntType> nttModulusRoot = { nttModulus, nttRoot };
	const ModulusRootPair<IntType> modulusRootPair = {  modulusRootInverse, nttModulusRoot };

#pragma omp critical
	{
		if (BluesteinFFT<VecType>::m_rootOfUnityTableByModulusRoot[nttModulusRoot].GetLength() == 0) {
			BluesteinFFT<VecType>::PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
		}

		if (BluesteinFFT<VecType>::m_powersTableByModulusRoot[modulusRootInverse].GetLength() == 0) {
			BluesteinFFT<VecType>::PreComputePowers(cycloOrder, modulusRootInverse);
		}

		if(BluesteinFFT<VecType>::m_RBTableByModulusRootPair[modulusRootPair].GetLength() == 0){
			BluesteinFFT<VecType>::PreComputeRBTable(cycloOrder, modulusRootPair);
		}
	}

	VecType inputToBluestein = Pad(element, cycloOrder, false);
	auto outputBluestein = BluesteinFFT<VecType>::ForwardTransform(inputToBluestein, rootInverse, cycloOrder, nttModulusRoot);
	auto cyclotomicInverse((IntType(cycloOrder)).ModInverse(modulus));
	outputBluestein = outputBluestein*cyclotomicInverse;
	VecType output = Drop(outputBluestein, cycloOrder, false, nttModulus, nttRoot);

	return output;
}

template<typename VecType>
VecType ChineseRemainderTransformArb<VecType>::Pad(const VecType& element, const usint cycloOrder, bool forward) {
	usint n = GetTotient(cycloOrder);

	const auto &modulus = element.GetModulus();
	VecType inputToBluestein(cycloOrder, modulus);

	if(forward){ // Forward transform padding
		for (usint i = 0; i < n; i++) {
			inputToBluestein[i]= element[i];
		}
	} else { // Inverse transform padding
		auto tList = GetTotientList(cycloOrder);
		usint i = 0;
		for (auto &coprime : tList) {
			inputToBluestein[coprime]= element[i++];
		}
	}

	return inputToBluestein;
}

template<typename VecType>
VecType ChineseRemainderTransformArb<VecType>::Drop(const VecType& element, const usint cycloOrder, bool forward, const IntType& bigMod, const IntType& bigRoot) {
	usint n = GetTotient(cycloOrder);

	const auto &modulus = element.GetModulus();
	VecType output(n, modulus);

	if(forward) { // Forward transform drop
		auto tList = GetTotientList(cycloOrder);
		for (usint i = 0; i < n; i++) {
			output[i]= element[tList[i]];
		}
	} else { // Inverse transform drop
		if((n+1) == cycloOrder) {
			// cycloOrder is prime: Reduce mod Phi_{n+1}(x)
			// Reduction involves subtracting the coeff of x^n from all terms
			auto coeff_n = element[n];

			//Precompute the Barrett mu parameter
			IntType mu = ComputeMu<IntType>(modulus);

			for (usint i = 0; i < n; i++) {
				output[i] = element[i].ModBarrettSub(coeff_n, modulus, mu);
			}
		} else if ((n+1)*2 == cycloOrder){
			// cycloOrder is 2*prime: 2 Step reduction
			// First reduce mod x^(n+1)+1 (=(x+1)*Phi_{2*(n+1)}(x))
			// Subtract co-efficient of x^(i+n+1) from x^(i)

			//Precompute the Barrett mu parameter
			IntType mu = ComputeMu<IntType>(modulus);

			for (usint i = 0; i < n; i++) {
				auto coeff_i = element[i];
				auto coeff_ip = element[i+n+1];
				output[i]= coeff_i.ModBarrettSub(coeff_ip, modulus, mu);
			}
			auto coeff_n = element[n].ModBarrettSub(element[2*n+1], modulus, mu);
			// Now reduce mod Phi_{2*(n+1)}(x)
			// Similar to the prime case but with alternating signs
			for (usint i = 0; i < n; i++) {
				if (i%2 == 0) {
					output[i]= output[i].ModBarrettSub(coeff_n, modulus, mu);
				} else {
					output[i]= output[i].ModBarrettAdd(coeff_n, modulus, mu);
				}
			}
		} else {
			//precompute root of unity tables for division NTT
			if ((m_rootOfUnityDivisionTableByModulus[bigMod].GetLength() == 0) || (m_DivisionNTTModulus[modulus] != bigMod)) {
				SetPreComputedNTTDivisionModulus(cycloOrder, modulus, bigMod, bigRoot);
			}

			// cycloOrder is arbitrary
			//auto output = PolyMod(element, this->m_cyclotomicPolyMap[modulus], modulus);

			const auto &nttMod = m_DivisionNTTModulus[modulus];
			const auto &rootTable = m_rootOfUnityDivisionTableByModulus[nttMod];
			VecType aPadded2(m_nttDivisionDim[cycloOrder], nttMod);
			//perform mod operation
			usint power = cycloOrder - n;
			for (usint i = n; i < element.GetLength(); i++) {
				aPadded2[power-(i-n)-1]= element[i];
			}

			VecType A(m_nttDivisionDim[cycloOrder]);
			NumberTheoreticTransform<VecType>::ForwardTransformIterative(aPadded2, rootTable, m_nttDivisionDim[cycloOrder], &A);
			auto AB = A*m_cyclotomicPolyReverseNTTMap[modulus];
			const auto &rootTableInverse = m_rootOfUnityDivisionInverseTableByModulus[nttMod];
			VecType a(m_nttDivisionDim[cycloOrder]);
			NumberTheoreticTransform<VecType>::InverseTransformIterative(AB, rootTableInverse, m_nttDivisionDim[cycloOrder], &a);

			VecType quotient(m_nttDivisionDim[cycloOrder], modulus);
			for (usint i = 0; i < power; i++) {
				quotient[i]= a[i];
			}
			quotient = quotient.Mod(modulus);
			quotient.SetModulus(nttMod);

			VecType newQuotient(m_nttDivisionDim[cycloOrder]);
			NumberTheoreticTransform<VecType>::ForwardTransformIterative(quotient, rootTable, m_nttDivisionDim[cycloOrder], &newQuotient);

			newQuotient = newQuotient*m_cyclotomicPolyNTTMap[modulus];

			VecType newQuotient2(m_nttDivisionDim[cycloOrder]);
			NumberTheoreticTransform<VecType>::InverseTransformIterative(newQuotient, rootTableInverse, m_nttDivisionDim[cycloOrder], &newQuotient2);
			newQuotient2.SetModulus(modulus);
			newQuotient2 = newQuotient2.Mod(modulus);


			//Precompute the Barrett mu parameter
			IntType mu = ComputeMu<IntType>(modulus);

			for (usint i = 0; i < n; i++) {
				output[i]= element[i].ModBarrettSub(newQuotient2[cycloOrder - 1 - i], modulus, mu);
			}
		}
	}
	return output;
}

template<typename VecType>
void ChineseRemainderTransformArb<VecType>::Reset() {
	m_cyclotomicPolyMap.clear();
	m_cyclotomicPolyReverseNTTMap.clear();
	m_cyclotomicPolyNTTMap.clear();
	m_rootOfUnityDivisionTableByModulus.clear();
	m_rootOfUnityDivisionInverseTableByModulus.clear();
	m_DivisionNTTModulus.clear();
	m_DivisionNTTRootOfUnity.clear();
	m_nttDivisionDim.clear();
	BluesteinFFT<VecType>::Reset();
}

}//namespace ends here
