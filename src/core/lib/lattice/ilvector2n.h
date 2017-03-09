/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 *
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 * This code provides basic lattice ideal manipulation functionality.
 */

#ifndef LBCRYPTO_LATTICE_ILVECTOR2N_H
#define LBCRYPTO_LATTICE_ILVECTOR2N_H

#include <vector>
#include <functional>
using std::function;
#include <memory>
using std::shared_ptr;

#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../utils/memory.h"
#include "../math/distrgen.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"
#include "../math/nbtheory.h"
#include "../math/transfrm.h"

namespace lbcrypto {

template<typename IntType, typename VecType, typename ParmType> class ILVectorImpl;

typedef ILVectorImpl<BigBinaryInteger, BigBinaryVector, ILParams> ILVector2n;
typedef ILVectorImpl<native64::BigBinaryInteger, native64::BigBinaryVector, ILNativeParams> ILVectorNative2n;

const usint SAMPLE_SIZE = 30; //!< @brief The maximum number of samples used for random variable sampling.

/**
 * @brief Ideal lattice using a vector representation
 */

template<typename IntType, typename VecType, typename ParmType>
class ILVectorImpl : public ILElement<ILVectorImpl<IntType,VecType,ParmType>,IntType,VecType>
{
public:

	typedef ParmType Params;
	typedef ILVectorImpl<IntType,VecType,ParmType> ILVectorType;

	/**
	 * Default constructor
	 */
	ILVectorImpl();

	/**
	 * Construct given parameters and format
	 * @param params - element parameters
	 * @param format - EVALUATION or COEFFICIENT
	 * @param initializeElementToZero - if true, allocates an empty vector set to all 0s
	 */
	ILVectorImpl(const shared_ptr<ParmType> params, Format format = EVALUATION, bool initializeElementToZero = false);

	/**
	 * Construct given parameters and format
	 * @param initializeElementToMax - if true, initializes entries in the vector to the maximum value
	 * @param params - element parameters
	 * @param format - EVALUATION or COEFFICIENT
	 */
	ILVectorImpl(bool initializeElementToMax, const shared_ptr<ParmType> params, Format format);

	/**
	 * Construct with a vector from a given generator
	 *
	 * @param &dgg the input discrete Gaussian Generator.
	 * @param &params the input params.
	 * @param format - EVALUATION or COEFFICIENT
	 */
	ILVectorImpl(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	 * Construct with a vector from a given generator
	 *
	 * @param &bug the input Binary Uniform Generator.
	 * @param &params the input params.
	 * @param format - EVALUATION or COEFFICIENT
	 */
	ILVectorImpl(const BinaryUniformGenerator &bug, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	 * Construct with a vector from a given generator
	 *
	 * @param &tug the input Ternary Uniform Generator.
	 * @param &params the input params.
	 * @param format - EVALUATION or COEFFICIENT
	 */
	ILVectorImpl(const TernaryUniformGenerator &tug, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	 * Construct with a vector from a given generator
	 *
	 * @param &dug the input discrete Uniform Generator.
	 * @param &params the input params.
	 * @param format - EVALUATION or COEFFICIENT
	 */
	ILVectorImpl(const DiscreteUniformGenerator &dug, const shared_ptr<ParmType> params, Format format = EVALUATION);

	/**
	 *  Create lambda that allocates a zeroed element for the case when it is called from a templated class
	 */
	inline static function<unique_ptr<ILVectorType>()> MakeAllocator(const shared_ptr<ParmType> params, Format format) {
		return [=]() {
			return lbcrypto::make_unique<ILVectorType>(params, format, true);
		};
	}

	/**
	 * Allocator for discrete uniform distribution.
	 *
	 * @param params ILParams instance that is is passed.
	 * @param resultFormat resultFormat for the polynomials generated.
	 * @param stddev standard deviation for the discrete gaussian generator.
	 * @return the resulting vector.
	 */
	inline static function<unique_ptr<ILVectorType>()> MakeDiscreteGaussianCoefficientAllocator(shared_ptr<ParmType> params, Format resultFormat, int stddev) {
		return [=]() {
			DiscreteGaussianGeneratorImpl<IntType,VecType> dgg(stddev);
			auto ilvec = lbcrypto::make_unique<ILVectorType>(dgg, params, COEFFICIENT);
			ilvec->SetFormat(resultFormat);
			return ilvec;
		};
	}

	/**
	 * Allocator for discrete uniform distribution.
	 *
	 * @param params ILParams instance that is is passed.
	 * @param format format for the polynomials generated.
	 * @return the resulting vector.
	 */
	inline static function<unique_ptr<ILVectorType>()> MakeDiscreteUniformAllocator(shared_ptr<ParmType> params, Format format) {
		return [=]() {
			DiscreteUniformGenerator dug(params->GetModulus());
			return lbcrypto::make_unique<ILVectorType>(dug, params, format);
		};
	}

	/**
	 * Copy constructor.
	 *
	 * @param &element the copied element.
	 */
	ILVectorImpl(const ILVectorType &element);

	/**
	 * Move constructor.
	 *
	 * @param &&element the copied element.
	 */
	ILVectorImpl(ILVectorType &&element);

	/**
	 * Clone the object by making a copy of it and returning the copy
	 * @return new Element
	 */
	ILVectorType Clone() const { return std::move(ILVectorImpl(*this)); }

	/**
	 * Clone the object, but have it contain nothing
	 * @return new Element
	 */
	ILVectorType CloneEmpty() const { return std::move( ILVectorImpl() ); }

	/**
	 * Clone
	 *
	 * Creates a new ILVectorImpl and clones only the params.
	 *  The tower values are empty. The tower values can be filled by another process/function or initializer list.
	 */
	ILVectorType CloneParametersOnly() const ;

	/**
	 * Clone with noise
	 *
	 * Creates a new ILVectorImpl and clones the params. The tower values will be filled up with noise based on the discrete gaussian.
	 *
	 * @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the ILVectorImpl with random numbers.
	 */
	ILVectorType CloneWithNoise(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, Format format) const;

	/**
	 * Destructor
	 */
	~ILVectorImpl();

	/**
	 * Assignment Operator.
	 *
	 * @param &rhs the ILVectorImpl to be copied.
	 * @return the resulting ILVectorImpl.
	 */
	const ILVectorType& operator=(const ILVectorType &rhs);

	/**
	 * Move Assignment.
	 *
	 * @param &rhs the ILVectorImpl to be copied.
	 * @return the resulting ILVectorImpl.
	 */
	const ILVectorType& operator=(ILVectorType &&rhs);

	/**
	 * Initalizer list
	 *
	 * @param &rhs the list to set the ILVectorImpl to.
	 * @return the resulting ILVectorImpl.
	 */
	const ILVectorType& operator=(std::initializer_list<sint> rhs);

	/**
	 * Assignment Operator. The usint val will be set at index zero and all other indices will be set to zero.
	 *
	 * @param val is the usint to assign to index zero.
	 * @return the resulting vector.
	 */
	const ILVectorType& operator=(usint val);

	//GETTERS
	/**
	 * Get method to get ILParams for the current vector.
	 *
	 * @return the ring element params.
	 */
	inline const shared_ptr<ILParams> GetParams() const { return m_params; }

	/**
	 * Get format of the element
	 *
	 * @return COEFFICIENT or EVALUATION
	 */
	Format GetFormat() const;

	/**
	 * Get the length of the element.
	 *
	 * @return length
	 */
	usint GetLength() const;

	/**
	 * Get modulus of the element
	 *
	 * @return the modulus.
	 */
	const IntType &GetModulus() const;

	/**
	 * Get the values for the element
	 *
	 * @return the vector.
	 */
	const VecType &GetValues() const;

	/**
	 * Get the cyclotomic order
	 *
	 * @return order
	 */
	const usint GetCyclotomicOrder() const;

	/**
	 * Get digit for a specific base.  Gets a binary polynomial from a given polynomial.  From every coefficient, it extracts the same digit.  Used in bit decomposition/relinearization operations.
	 *
	 * @param index is the index to get.
	 * @param base is the base the result should be in.
	 * @return is the result.
	 */
	ILVectorImpl GetDigitAtIndexForBase(usint index, usint base) const;

	/**
	 * Get the root of unity.
	 *
	 * @return the root of unity.
	 */
	const IntType &GetRootOfUnity() const;


	/**
	 * Get value of binaryvector at index i.
	 *
	 * @return value at index i.
	 */
	const IntType& GetValAtIndex(usint i) const;

	//SETTERS
	/**
	 *  Set VecType value to val
	 *
	 * @param index is the index at which the value is to be set.
	 * @param val is the value to be set.
	 */
	inline void SetValAtIndex(size_t index, int val) {
		m_values->SetValAtIndex(index, IntType(val));
	}

	/**
	 *  Set VecType value to val
	 *
	 * @param index is the index at which the value is to be set.
	 * @param val is the value to be set.
	 */
	inline void SetValAtIndex(size_t index, const IntType& val) {
		m_values->SetValAtIndex(index, val);
	}

	/**
	 * Set method of the values.
	 *
	 * @param values is the set of values of the vector.
	 * @param format is the format.
	 */
	void SetValues(const VecType& values, Format format);

	/**
	 * Sets all values to zero.
	 */
	void SetValuesToZero();

	/**
	 * Sets all values to maximum.
	 */
	void SetValuesToMax();

	/**
	 * Sets the format.
	 *
	 * @param format is the Format to be set.
	 */
	void SetFormat(const Format format);

	/**
	 * Scalar addition - add an element to the first index only.
	 * This operation is only allowed in COEFFICIENT format.
	 *
	 * @param &element is the element to add entry-wise.
	 * @return is the return of the addition operation.
	 */
	ILVectorImpl Plus(const IntType &element) const;

	/**
	 * Scalar subtraction - subtract an element to all entries.
	 *
	 * @param &element is the element to subtract entry-wise.
	 * @return is the return value of the minus operation.
	 */
	ILVectorImpl Minus(const IntType &element) const;

	/**
	 * Scalar multiplication - multiply all entries.
	 *
	 * @param &element is the element to multiply entry-wise.
	 * @return is the return value of the times operation.
	 */
	ILVectorImpl Times(const IntType &element) const;

	/**
	 * Performs an addition operation and returns the result.
	 *
	 * @param &element is the element to add with.
	 * @return is the result of the addition.
	 */
	ILVectorImpl Plus(const ILVectorImpl &element) const;

	/**
	 * Performs a subtraction operation and returns the result.
	 *
	 * @param &element is the element to subtract with.
	 * @return is the result of the subtraction.
	 */
	ILVectorImpl Minus(const ILVectorImpl &element) const;

	/**
	 * Performs a multiplication operation and returns the result.
	 *
	 * @param &element is the element to multiply with.
	 * @return is the result of the multiplication.
	 */
	ILVectorImpl Times(const ILVectorImpl &element) const;

	/**
	 * Performs += operation with a IntType and returns the result.
	 *
	 * @param &element is the element to add
	 * @return is the result of the addition.
	 */
	const ILVectorImpl& operator+=(const IntType &element) {
		return *this = this->Plus(element);
	}

	/**
	 * Performs -= operation with a IntType and returns the result.
	 *
	 * @param &element is the element to subtract
	 * @return is the result of the addition.
	 */
	const ILVectorImpl& operator-=(const IntType &element) {
		SetValues( GetValues().ModSub(element), this->m_format );
		return *this;
	}

	/**
	 * Performs *= operation with a IntType and returns the result.
	 *
	 * @param &element is the element to multiply by
	 * @return is the result of the multiplication.
	 */
	const ILVectorImpl& operator*=(const IntType &element) {
		SetValues( GetValues().ModMul(element), this->m_format );
		return *this;
	}

	/**
	 * Performs an addition operation and returns the result.
	 *
	 * @param &element is the element to add
	 * @return is the result of the addition.
	 */
	const ILVectorImpl& operator+=(const ILVectorImpl &element);

	/**
	 * Performs an subtraction operation and returns the result.
	 *
	 * @param &element is the element to subtract
	 * @return is the result of the addition.
	 */
	const ILVectorImpl& operator-=(const ILVectorImpl &element);

	/**
	 * Performs an multiplication operation and returns the result.
	 *
	 * @param &element is the element to multiply by
	 * @return is the result of the multiplication.
	 */
	const ILVectorImpl& operator*=(const ILVectorImpl &element);

	/**
	 * Equal operator compares this ILVectorImpl to the specified ILVectorImpl
	 *
	 * @param &rhs is the specified ILVectorImpl to be compared with this ILVectorImpl.
	 * @return true if this ILVectorImpl represents the same values as the specified ILVectorArray2n, false otherwise
	 */
	inline bool operator==(const ILVectorImpl &rhs) const {
		if (this->GetFormat() != rhs.GetFormat()) {
			return false;
		}
		if(m_params->GetRootOfUnity() != rhs.GetRootOfUnity()) {
			return false;
		}
		if (this->GetValues() != rhs.GetValues()) {
			return false;
		}
		return true;
	}

	/**
	 * Scalar multiplication followed by division and rounding operation - operation on all entries.
	 *
	 * @param &p is the integer muliplicand.
	 * @param &q is the integer divisor.
	 * @return is the return value of the multiply, divide and followed by rounding operation.
	 */
	ILVectorImpl MultiplyAndRound(const IntType &p, const IntType &q) const;

	/**
	 * Scalar division followed by rounding operation - operation on all entries.
	 *
	 * @param &q is the element to divide entry-wise.
	 * @return is the return value of the divide, followed by rounding operation.
	 */
	ILVectorImpl DivideAndRound(const IntType &q) const;

	/**
	 * Performs a negation operation and returns the result.
	 *
	 * @return is the result of the negation.
	 */
	ILVectorImpl Negate() const;

	// OTHER METHODS

	/**
	 * Adds one to every entry of the ILVectorImpl.
	 */
	void AddILElementOne();

	/**
	 * Performs an automorphism transform operation and returns the result.
	 *
	 * @param &i is the element to perform the automorphism transform with.
	 * @return is the result of the automorphism transform.
	 */
	ILVectorImpl AutomorphismTransform(const usint &i) const;

	/**
	 * Interpolates based on the Chinese Remainder Transform Interpolation.
	 * Does nothing for ILVectorImpl. Needed to support the linear CRT interpolation in ILVectorArray2n.
	 *
	 * @return the original ring element.
	 */
	ILVectorImpl CRTInterpolate() const { return *this; }

	/**
	 * Transpose the ring element using the automorphism operation
	 *
	 * @return is the result of the transposition.
	 */
	ILVectorImpl Transpose() const;

	/**
	 * Performs a multiplicative inverse operation and returns the result.
	 *
	 * @return is the result of the multiplicative inverse.
	 */
	ILVectorImpl MultiplicativeInverse() const;

	/**
	 * Perform a modulus by 2 operation.  Returns the least significant bit.
	 *
	 * @return is the return value of the modulus by 2, also the least significant bit.
	 */
	ILVectorImpl ModByTwo() const;

	/**
	 * Modulus - perform a modulus operation. Does proper mapping of [-modulus/2, modulus/2) to [0, modulus)
	 *
	 * @param modulus is the modulus to use.
	 * @return is the return value of the modulus.
	 */
	ILVectorImpl SignedMod(const IntType &modulus) const;

	/**
	 * Switch modulus and adjust the values
	 *
	 * @param &modulus is the modulus to be set.
	 * @param &rootOfUnity is the corresponding root of unity for the modulus
	 * ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus.
	 */
	void SwitchModulus(const IntType &modulus, const IntType &rootOfUnity);

	/**
	 * Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
	 */
	void SwitchFormat();

	/**
	 * Prints values of the ILVectorImpl.
	 */
	void PrintValues() const;

	/**
	 * Make ILVectorArray2n Sparse for SHE KeyGen operations. Sets every index not equal to zero mod the wFactor to zero.
	 *
	 * @param &wFactor ratio between the original ILVectorArray2n's ring dimension and the new ring dimension.
	 */
	void MakeSparse(const IntType &wFactor);

	/**
	 * Interleaves values in the ILVectorImpl with odd indices being all zeros.
	 */
	void Decompose();

	/**
	 * Returns true if the vector is empty/ m_values==NULL
	 */
	bool IsEmpty() const;

	/**
	 * Determines if inverse exists
	 *
	 * @return is the Boolean representation of the existence of multiplicative inverse.
	 */
	bool InverseExists() const;

	/**
	 * Returns the infinity norm, basically the largest value in the ring element.
	 *
	 * @return is the largest value in the ring element.
	 */
	double Norm() const;

	/**
	 * Rounds the polynomial to an input integer.
	 *
	 * @param x is integer to round to.
	 * @return is the result of the rounding operation.
	 */
	ILVectorImpl Round(const IntType& x) const;

	/**
	 * Write vector x (current value of the ILVectorImpl object) as \sum\limits{i=0}^{\lfloor {\log q/base} \rfloor} {(base^i u_i)} and
	 * return the vector of {u_0, u_1,...,u_{\lfloor {\log q/base} \rfloor}} \in R_base^{\lceil {\log q/base} \rceil};
	 * used as a subroutine in the relinearization procedure
	 *
	 * @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
	 * @result is the pointer where the base decomposition vector is stored
	 */
	std::vector<ILVectorImpl> BaseDecompose(usint baseBits) const;

	/**
	 * Generate a vector of ILVectorImpl's as {x, base*x, base^2*x, ..., base^{\lfloor {\log q/base} \rfloor}*x, where x is the current ILVectorImpl object;
	 * used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element
	 *
	 * @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
	 * @result is the pointer where the base decomposition vector is stored
	 */
	std::vector<ILVectorImpl> PowersOfBase(usint baseBits) const;

	/**
	 * Shift entries in the vector left a specific number of entries.
	 *
	 * @param n the number of entries to shift left.
	 * @return is the resulting vector from shifting left.
	 */
	ILVectorImpl ShiftLeft(unsigned int n) const;

	/**
	 * Shift entries in the vector right a specific number of entries.
	 *
	 * @param n the number of entries to shift right.
	 * @return is the resulting vector from shifting right.
	 */
	ILVectorImpl ShiftRight(unsigned int n) const;

	/**
	 * Pre computes the Dgg samples.
	 *
	 * @param &dgg the discrete Gaussian Generator.
	 * @param &params are the relevant ring parameters.
	 */
	static void PreComputeDggSamples(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, const shared_ptr<ParmType> params);

	/**
	 * Pre computes the Tug samples.
	 *
	 * @param &tug the ternary uniform generator.
	 * @param &params are the relevant ring parameters.
	 */
	static void PreComputeTugSamples(const TernaryUniformGenerator &tug, const shared_ptr<ParmType> params);

	/**
	 * Clear the pre-computed discrete Gaussian samples.
	 */
	static void DestroyPreComputedSamples() {
		m_dggSamples.clear();
	}

	/**
	 * Clear the pre-computed ternary uniform samples.
	 */
	static void DestroyPreComputedTugSamples() {
		m_tugSamples.clear();
	}

	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const;

	/**
	 * Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj);

	friend inline std::ostream& operator<<(std::ostream& os, const ILVectorImpl& vec) {
		os << vec.GetValues();
		return os;
	}

	friend inline ILVectorImpl operator+(const ILVectorImpl &a, const ILVectorImpl &b) { return a.Plus(b); }
	friend inline ILVectorImpl operator+(const ILVectorImpl &a, const IntType &b) { return a.Plus(b); }
	friend inline ILVectorImpl operator+(const IntType &a, const ILVectorImpl &b) { return b.Plus(a); }
	friend inline ILVectorImpl operator-(const ILVectorImpl &a, const ILVectorImpl &b) { return a.Minus(b); }
	friend inline ILVectorImpl operator-(const ILVectorImpl &a, const IntType &b) { return a.Minus(b); }
	friend inline ILVectorImpl operator*(const ILVectorImpl &a, const ILVectorImpl &b) { return a.Times(b); }
	friend inline ILVectorImpl operator*(const ILVectorImpl &a, const IntType &b) { return a.Times(b); }
	friend inline ILVectorImpl operator*(const IntType &a, const ILVectorImpl &b) { return b.Times(a); }

private:

	// stores either coefficient or evaluation representation
	VecType *m_values;

	// 1 for coefficient and 0 for evaluation format
	Format m_format;

	// noise norm associated with this vector - to be defined later
	// IntType m_norm;

	// parameters for ideal lattices
	shared_ptr<ParmType> m_params;

	// static variables to store pre-computed samples and the parms that went with them
	static std::vector<ILVectorImpl> m_dggSamples;
	static shared_ptr<ParmType> m_dggSamples_params;

	// static variables to store pre-computed samples and the parms that went with them
	static std::vector<ILVectorImpl> m_tugSamples;
	static shared_ptr<ParmType> m_tugSamples_params;

	// static variable to store the sample size for each set of ILParams
	static const usint m_sampleSize = SAMPLE_SIZE;

	// gets a random discrete Gaussian polynomial
	static const ILVectorImpl GetPrecomputedVector();

	// gets a random polynomial generated using ternary uniform distribution
	static const ILVectorImpl GetPrecomputedTugVector();
};

} // namespace lbcrypto ends

#endif
