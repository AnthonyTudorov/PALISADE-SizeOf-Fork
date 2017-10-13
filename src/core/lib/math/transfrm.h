/**
 * @file transfrm.h This file contains the linear transform interface functionality.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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

#ifndef LBCRYPTO_MATH_TRANSFRM_H
#define LBCRYPTO_MATH_TRANSFRM_H


#include "backend.h"
#include "nbtheory.h"
#include "../utils/utilities.h"
#include <chrono>
#include <complex>
#include <time.h>
#include <map>
#include <fstream>
#include <thread>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	/**
	* @brief Number Theoretic Transform implemetation
	*/
	template<typename IntType, typename VecType>
	class NumberTheoreticTransform
	{
	public:
		/**
		* Forward transform.
		*
		* @param element is the element to perform the transform on.
		* @param rootOfUnityTable the root of unity table.
		* @param cycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		static void ForwardTransformIterative(const VecType& element, const VecType &rootOfUnityTable, const usint cycloOrder, VecType* result) {
	        bool dbg_flag = false;
		usint n = cycloOrder;

		auto modulus = element.GetModulus();

		if( result->GetLength() != n )
			throw std::logic_error("Vector for NumberTheoreticTransform::ForwardTransformIterative size needs to be == cyclotomic order");
		result->SetModulus(modulus);

		//reverse coefficients (bit reversal)
		usint msb = GetMSB64(n - 1);
		for (size_t i = 0; i < n; i++)
			result->SetValAtIndex(i, element.GetValAtIndex(ReverseBits(i, msb)));

		IntType omegaFactor;
		IntType product;
		IntType butterflyPlus;
		IntType butterflyMinus;

		/*Ring dimension factor calculates the ratio between the cyclotomic order of the root of unity table
			  that was generated originally and the cyclotomic order of the current VecType. The twiddle table
			  for lower cyclotomic orders is smaller. This trick only works for powers of two cyclotomics.*/
		int ringDimensionFactor = rootOfUnityTable.GetLength() / cycloOrder;
		DEBUG("table size " << rootOfUnityTable.GetLength());
		DEBUG("ring dimension factor " << ringDimensionFactor);

		//Precompute the Barrett mu parameter
#if !defined(NTL_SPEEDUP)
		IntType mu = ComputeMu<IntType>(element.GetModulus());
#else
		IntType modulus = element.GetModulus();
#endif

		usint logn = log2(n);

		for (usint logm = 1; logm <= logn; logm++)
		{
			// calculate the i indexes into the root table one time per loop
			vector<usint> indexes(1 << (logm-1));
			for (usint i = 0; i < (usint)(1 << (logm-1)); i++) {
				indexes[i] = (i << (1+logn-logm)) * ringDimensionFactor;
			}

			for (usint j = 0; j<n; j = j + (1 << logm))
			{
				for (usint i = 0; i < (usint)(1 << (logm-1)); i++)
				{
					const IntType& omega = rootOfUnityTable.GetValAtIndex(indexes[i]);

					usint indexEven = j + i;
					usint indexOdd = indexEven + (1 << (logm-1));
					auto oddVal = result->GetValAtIndex(indexOdd);
					auto oddMSB = oddVal.GetMSB();
					auto evenVal = result->GetValAtIndex(indexEven);

					if (oddMSB > 0)
					{
						if (oddMSB == 1)
							omegaFactor = omega;
						else
						{
#if !defined(NTL_SPEEDUP)

							omegaFactor = omega.ModBarrettMul(result->GetValAtIndex(indexOdd),element.GetModulus(), mu);

#else
							omegaFactor = omega.ModMulFast(result->GetValAtIndex(indexOdd),modulus);
#endif
							DEBUG("omegaFactor "<<omegaFactor);
						}

#if !defined(NTL_SPEEDUP)

						butterflyPlus = evenVal;
						butterflyPlus += omegaFactor;
						if (butterflyPlus >= modulus)
							butterflyPlus -= modulus;

						butterflyMinus = evenVal;
						if (evenVal < omegaFactor)
							butterflyMinus += modulus;
						butterflyMinus -= omegaFactor;

						result->SetValAtIndex(indexEven, butterflyPlus);
						result->SetValAtIndex(indexOdd, butterflyMinus);
#else
						(*result)[indexOdd] = (*result)[indexEven].ModSubFast(omegaFactor,modulus);
						(*result)[indexEven] = (*result)[indexEven].ModAddFast(omegaFactor,modulus);
#endif

					}
					else
					  (*result)[indexOdd] = (*result)[indexEven];
				}
			}
		}

		return;

	}


		/**
		* Inverse transform.
		*
		* @param element is the element to perform the transform on.
		* @param rootOfUnityInverseTable the root of unity table.
		* @param cycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		static void InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable, const usint cycloOrder, VecType *transform);
	};

	/**
	* @brief Chinese Remainder Transform implemetation.  This is a refined, higher performance implementation.
	*/
	template<typename IntType, typename VecType>
	class ChineseRemainderTransform
	{
	public:
		/**
		* Virtual forward transform.
		*
		* @param &element is the element to perform the transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		static void ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder, VecType *ans);


		/**
		* Virtual inverse transform.
		*
		* @param &element is the element to perform the inverse transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the inverse transform.
		*/
		static void InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder, VecType *transform);

		/**
		* Reset cached values for the transform to empty.
		*/
		static void Reset();

	private:
		static VecType *m_rootOfUnityTable;
		static VecType *m_rootOfUnityInverseTable;
	};

	/**
	* @brief Golden Chinese Remainder Transform FFT implemetation.
	*/
	template<typename IntType, typename VecType>
	class ChineseRemainderTransformFTT
	{
	public:
		/**
		* Virtual forward transform.
		*
		* @param &element is the element to perform the transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		static void ForwardTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder, VecType *OpFFT) {

			if( OpFFT->GetLength() != CycloOrder/2 )
				throw std::logic_error("Vector for ChineseRemainderTransformFTT::ForwardTransform size must be == CyclotomicOrder/2");

			if (rootOfUnity == 1 || rootOfUnity == 0)
				throw std::logic_error("Root of unity for ChineseRemainderTransformFTT::ForwardTransform cannot be zero or one");

			if (!IsPowerOfTwo(CycloOrder))
				throw std::logic_error("CyclotomicOrder for ChineseRemainderTransformFTT::ForwardTransform is not a power of two");

#if !defined(NTL_SPEEDUP)
			//Precompute the Barrett mu parameter
			IntType mu = ComputeMu<IntType>(element.GetModulus());
#endif

			const VecType *rootOfUnityTable = NULL;

			// check to see if the modulus is in the table, and add it if it isn't
		#pragma omp critical
			{
				bool recompute = false;
				auto mSearch = m_rootOfUnityTableByModulus.find(element.GetModulus());

				if( mSearch != m_rootOfUnityTableByModulus.end() ) {
					// i found it... make sure it's kosher
					if( mSearch->second.GetLength() == 0 || mSearch->second.GetValAtIndex(1) != rootOfUnity ) {
						recompute = true;
					}
					else
						rootOfUnityTable = &mSearch->second;
				}

				if( mSearch == m_rootOfUnityTableByModulus.end() || recompute ){
					VecType rTable(CycloOrder / 2);
					IntType modulus(element.GetModulus());
					IntType x(1);

					for (usint i = 0; i<CycloOrder / 2; i++) {
						rTable.SetValAtIndex(i, x);
#if defined(NTL_SPEEDUP)
						x = x.ModMul(rootOfUnity, modulus);
#else
						x = x.ModBarrettMul(rootOfUnity, modulus, mu);
#endif
					}

					rootOfUnityTable = &(m_rootOfUnityTableByModulus[modulus] = std::move(rTable));
				}
			}

			VecType InputToFFT(element);

			usint ringDimensionFactor = rootOfUnityTable->GetLength() / (CycloOrder / 2);

			//Fermat Theoretic Transform (FTT)
			for (usint i = 0; i<CycloOrder / 2; i++)
#if defined(NTL_SPEEDUP)
				InputToFFT[i] = element[i].ModMul((*rootOfUnityTable)[i*ringDimensionFactor], element.GetModulus());
#else
				InputToFFT.SetValAtIndex(i, element.GetValAtIndex(i).ModBarrettMul(rootOfUnityTable->GetValAtIndex(i*ringDimensionFactor), element.GetModulus(), mu));
#endif

			NumberTheoreticTransform<IntType,VecType>::ForwardTransformIterative(InputToFFT, *rootOfUnityTable, CycloOrder / 2, OpFFT);

			return;
		}


		/**
		* Virtual inverse transform.
		*
		* @param &element is the element to perform the inverse transform on.
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @return is the output result of the inverse transform.
		*/
		static void InverseTransform(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder, VecType *transform);

		/**
		* Precomputation of root of unity tables.
		*
		* @param rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @param modulus is the modulus
		*/
		static void PreCompute(const IntType& rootOfUnity, const usint CycloOrder, const IntType &modulus);

		/**
		* Precomputation of root of unity tables.
		*
		* @param &rootOfUnity the root of unity.
		* @param CycloOrder is the cyclotomic order.
		* @param &moduliiChain is the modulus
		*/
		static void PreCompute(std::vector<IntType> &rootOfUnity, const usint CycloOrder, std::vector<IntType> &moduliiChain);

		/**
		* Reset cached values for the transform to empty.
		*/
		static void Reset();

	//private:
		static std::map<IntType, VecType> m_rootOfUnityTableByModulus;
		static std::map<IntType, VecType> m_rootOfUnityInverseTableByModulus;
	};

	/**
	* @brief Discrete Fourier Transform FFT implemetation.
	*/
	class DiscreteFourierTransform
	{
	public:
		/**
		* Virtual FFT forward transform.
		*
		* @param A is the element to perform the transform on.
		* @return is the output result of the transform.
		*/
		static std::vector<std::complex<double>> FFTForwardTransform(std::vector<std::complex<double>>& A);

		/**
		* Virtual FFT inverse transform.
		*
		* @param A is the element to perform the inverse transform on.
		* @return is the output result of the inverse transform.
		*/
		static std::vector<std::complex<double>> FFTInverseTransform(std::vector<std::complex<double>>& A);

		/**
		* Virtual forward transform.
		*
		* @param A is the element to perform the transform on.
		* @return is the output result of the transform.
		*/
		static std::vector<std::complex<double>> ForwardTransform(std::vector<std::complex<double>> A);

		/**
		* Virtual inverse transform.
		*
		* @param A is the element to perform the inverse transform on.
		* @return is the output result of the inverse transform.
		*/
		static std::vector<std::complex<double>> InverseTransform(std::vector<std::complex<double>> A);

		/**
		* Reset cached values for the transform to empty.
		*/
		static void Reset();

		static void PreComputeTable(uint32_t s);

	private:
		static std::complex<double>* rootOfUnityTable;
	};

	// struct used as a key in BlueStein transform
	template<typename IntType>
	using ModulusRoot = std::pair<IntType, IntType>;

	template<typename IntType>
	using ModulusRootPair = std::pair<ModulusRoot<IntType>, ModulusRoot<IntType>>;

	/**
	* @brief Bluestein Fast Fourier Transform implemetation
	*/
	template<typename IntType, typename VecType>
	class BluesteinFFT {
	public:
		/**
		* Forward transform.
		*
		* @param element is the element to perform the transform on.
		* @param rootOfUnityTable the root of unity table.
		* @param cycloOrder is the cyclotomic order.
		* @return is the output result of the transform.
		*/
		static VecType ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder);
		static VecType ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder, const ModulusRoot<IntType>& nttModulusRoot);

		/**
		*
		* @param a is the input vector to be padded with zeros.
		* @param finalSize is the length of the output vector.
		* @return output vector padded with (finalSize - initial size)additional zeros.
		*/
		static VecType PadZeros(const VecType &a, const usint finalSize);

		/**
		*
		* @param a is the input vector to be resized.
		* @param lo is lower coefficient index.
		* @param hi is higher coefficient index.
		* @return output vector s.t output vector = a[lo]...a[hi].
		*/
		static VecType Resize(const VecType &a, usint  lo, usint hi);

		// void PreComputeNTTModulus(usint cycloOrder, const std::vector<IntType> &modulii);

		/**
		* @brief Precomputes the modulus needed for NTT operation in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial.
		* @param modulus is the modulus of the polynomial.
		*/
		static void PreComputeDefaultNTTModulusRoot(usint cycloOrder, const IntType &modulus);

		/**
		* @brief Precomputes the root of unity table needed for NTT operation in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial.
		*/
		static void PreComputeRootTableForNTT(usint cycloOrder, const ModulusRoot<IntType> &nttModulusRoot);

		/**
		* @brief precomputes the powers of root used in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		* @param root is the root of unity s.t. root^2m = 1.
		*/
		static void PreComputePowers(usint cycloOrder, const ModulusRoot<IntType> &modulusRoot);

		/**
		* @brief precomputes the NTT transform of the power of root of unity used in the Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		* @param root is the root of unity s.t. root^2m = 1.
		* @param bigMod is the modulus required for the NTT transform.
		* @param bigRoot is the root of unity required for the NTT transform.
		*/
		static void PreComputeRBTable(usint cycloOrder, const ModulusRootPair<IntType> &modulusRootPair);

		/**
		* Reset cached values for the transform to empty.
		*/
		static void Reset();

		//map to store the root of unity table with modulus as key.
		static std::map<ModulusRoot<IntType>, VecType> m_rootOfUnityTableByModulusRoot;

		//map to store the root of unity inverse table with modulus as key.
		static std::map<ModulusRoot<IntType>, VecType> m_rootOfUnityInverseTableByModulusRoot;

		//map to store the power of roots as a table with modulus + root of unity as key.
		static std::map<ModulusRoot<IntType>, VecType> m_powersTableByModulusRoot;

		//map to store the forward transform of power table with modulus + root of unity as key.
		static std::map<ModulusRootPair<IntType>, VecType> m_RBTableByModulusRootPair;

	private:
		//map to store the precomputed NTT modulus with modulus as key.
		static std::map<IntType, ModulusRoot<IntType>> m_defaultNTTModulusRoot;

	};

	/**
	* @brief Chinese Remainder Transform for arbitrary cyclotomics.
	*/
	template<typename IntType, typename VecType>
	class ChineseRemainderTransformArb {
	public:
		/**
		* Sets the cyclotomic polynomial.
		*
		*/
		static void SetCylotomicPolynomial(const VecType &poly, const IntType &mod);

		/**
		* Forward transform.
		*
		* @param element is the element to perform the transform on.
		* @param root is the 2mth root of unity w.r.t the ring modulus.
		* @param cycloOrder is the cyclotomic order of the ring element.
		* @param bigMod is the addtional modulus needed for NTT operation.
		* @param bigRoot is the addtional root of unity w.r.t bigMod needed for NTT operation.
		* @return is the output result of the transform.
		*/
		static VecType ForwardTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot, const usint cycloOrder);

		/**
		* Inverse transform.
		*
		* @param element is the element to perform the transform on.
		* @param root is the 2mth root of unity w.r.t the ring modulus.
		* @param cycloOrder is the cyclotomic order of the ring element.
		* @param bigMod is the addtional modulus needed for NTT operation.
		* @param bigRoot is the addtional root of unity w.r.t bigMod needed for NTT operation.
		* @return is the output result of the transform.
		*/
		static VecType InverseTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot, const usint cycloOrder);

		/**
		* Reset cached values for the transform to empty.
		*/
		static void Reset();
		
		/**
		* @brief Precomputes the root of unity and modulus needed for NTT operation in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		*/
		static void PreCompute(const usint cyclotoOrder, const IntType &modulus);

		/**
		* @brief Sets the precomputed root of unity and modulus needed for NTT operation in forward Bluestein transform.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		* @param nttMod is the modulus needed for the NTT operation in forward Bluestein transform.
		* @param nttRoot is the root of unity needed for the NTT operation in forward Bluestein transform.
		*/
		static void SetPreComputedNTTModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod, const IntType &nttRoot);
		
		/**
		* @brief Sets the precomputed root of unity and modulus needed for NTT operation and computes m_cyclotomicPolyReveseNTTMap,m_cyclotomicPolyNTTMap.
		* Always called after setting the cyclotomic polynomial.
		* @param cycloOrder is the cyclotomic order of the polynomial ring.
		* @param modulus is the modulus of the polynomial ring.
		* @param nttMod is the modulus needed for the NTT operation in forward Bluestein transform.
		* @param nttRoot is the root of unity needed for the NTT operation in forward Bluestein transform.
		*/
		static void SetPreComputedNTTDivisionModulus(usint cyclotoOrder, const IntType &modulus, const IntType &nttMod, const IntType &nttRoot);

		/**
		* @brief Computes the inverse of the cyclotomic polynomial using Newton-Iteration method.
		* @param cycloPoly is the cyclotomic polynomial.
		* @param modulus is the modulus of the polynomial ring.
		* @return inverse polynomial. 
		*/
		static VecType InversePolyMod(const VecType &cycloPoly, const IntType &modulus, usint power);

	private:
		static VecType Pad(const VecType& element, const usint cycloOrder, bool forward);

		static VecType Drop(const VecType& element, const usint cycloOrder, bool forward, const IntType& bigMod, const IntType& bigRoot);

		//map to store the cyclotomic polynomial with polynomial ring's modulus as key.
		static std::map<IntType, VecType> m_cyclotomicPolyMap;

		//map to store the forward NTT transform of the inverse of cyclotomic polynomial with polynomial ring's modulus as key.
		static std::map<IntType, VecType> m_cyclotomicPolyReverseNTTMap;

		//map to store the forward NTT transform of the cyclotomic polynomial with polynomial ring's modulus as key.
		static std::map<IntType, VecType> m_cyclotomicPolyNTTMap;

		//map to store the root of unity table used in NTT based polynomial division.
		static std::map<IntType, VecType> m_rootOfUnityDivisionTableByModulus;

		//map to store the root of unity table for computing forward NTT of inverse cyclotomic polynomial used in NTT based polynomial division.
		static std::map<IntType, VecType> m_rootOfUnityDivisionInverseTableByModulus;

		//modulus used in NTT based polynomial division.
		static std::map<IntType, IntType> m_DivisionNTTModulus;

		//root of unity used in NTT based polynomial division.
		static std::map<IntType, IntType> m_DivisionNTTRootOfUnity;

		//dimension of the NTT transform in NTT based polynomial division.
		static std::map<usint, usint> m_nttDivisionDim;

	};



} // namespace lbcrypto ends

#endif
