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

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	const usint SAMPLE_SIZE = 30; //!< @brief The maximum number of samples used for random variable sampling.

								  /**
								  * @brief Ideal lattice in vector representation or a vector in the double-CRT "matrix".  This is not fully implemented and is currently only stubs.
								  */
	//JSON FACILITY
	class ILVector2n : public ILElement, public Serializable
	{
	public:

		/**
		* Constructor that initializes nothing.
		*/
		ILVector2n();

		/**
		* Constructor that initializes parameters.
		*
		* @param &params element parameters.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
        // ILVector2n(const ElemParams &params, Format format = EVALUATION);

        ILVector2n(const ElemParams &params, Format format = EVALUATION, bool initializeElementToZero = false);

		// void GenerateNoise(DiscreteGaussianGenerator &dgg, Format format = EVALUATION) ;

		/**
		* Constructor based on full methods.
		*
		* @param &dgg the input discrete Gaussian Generator.
		* @param &params the input params.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVector2n(const DiscreteGaussianGenerator &dgg, const ElemParams &params, Format format = EVALUATION);
		
		/**
		* Constructor based on full methods.
		*
		* @param &dbg the input Binary Uniform Generator.
		* @param &params the input params.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVector2n(const BinaryUniformGenerator &bug, const ElemParams &params, Format format = EVALUATION);

		/**
		* Constructor based on full methods.
		*
		* @param &dug the input discrete Uniform Generator.
		* @param &params the input params.
		* @param &format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVector2n(const DiscreteUniformGenerator &dug, const ElemParams &params, Format format = EVALUATION);

        /**
         *  Create lambda that allocates a zeroed element with the specified
         *  parameters and format
         */
        inline static function<unique_ptr<ILVector2n>()> MakeAllocator(ILParams params, Format format) {
            return [=]() {
                return make_unique<ILVector2n>(params, format, true);
            };
        }

        /**
         *  Create lambda that allocates a zeroed element for the case when it is called from a templated class
         */
        inline static function<unique_ptr<ILVector2n>()> MakeAllocator(const ElemParams *params, Format format) {
            return [=]() {
                //return MakeAllocator(*(static_cast<const ILParams*>(params)),format);
				return make_unique<ILVector2n>(*(dynamic_cast<const ILParams*>(params)), format, true);
            };
        }

		/**
		* Allocator for discrete uniform distribution.
		*
		* @param params ILParams instance that is is passed.
		* @param resultFormat resultFormat for the polynomials generated.
		* @param stddev standard deviation for the dicrete gaussian generator.
		* @return the resulting vector.
		*/
        inline static function<unique_ptr<ILVector2n>()> MakeDiscreteGaussianCoefficientAllocator(ILParams params, Format resultFormat, int stddev) {
            return [=]() {
                DiscreteGaussianGenerator dgg(stddev);
                auto ilvec = make_unique<ILVector2n>(dgg, params, COEFFICIENT);
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
        inline static function<unique_ptr<ILVector2n>()> MakeDiscreteUniformAllocator(ILParams params, Format format) {
            return [=]() {
                DiscreteUniformGenerator dug(params.GetModulus());
                return make_unique<ILVector2n>(dug, params, format);
            };
        }

		/**
		* Copy constructor.
		*
		* @param &element the copied element.
		*/
		ILVector2n(const ILVector2n &element);

		/**
		* Move constructor.
		*
		* @param &&element the copied element.
		*/
		ILVector2n(ILVector2n &&element);

		/**
		* Assignment Operator.
		*
		* @param &rhs the ILVector2n to be copied.
		* @return the resulting ILVector2n.
		*/
		const ILVector2n& operator=(const ILVector2n &rhs);

		/**
		* Move Operator.
        *
		* @param &rhs the ILVector2n to be copied.
		* @return the resulting ILVector2n.
        */
        const ILVector2n& operator=(ILVector2n &&rhs);

		/**
		* Initalizer list
		*
		* @param &rhs the list to set the ILVector2n to.
		* @return the resulting ILVector2n.
		*/
		const ILVector2n& operator=(std::initializer_list<sint> rhs);

        //CLONE OPERATIONS
		/**
		* Clone
		*
		* Creates a new ILVector2n and clones only the params. The tower values are empty. The tower values can be filled by another process/function or initializer list.
		*/
		ILVector2n CloneWithParams() const ;

		/**
		* Clone with noise
		*
		* Creates a new ILVector2n and clones the params. The tower values will be filled up with noise based on the discrete gaussian.
		*
		* @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the ILVector2n with random numbers.
		*/
		ILVector2n CloneWithNoise(const DiscreteGaussianGenerator &dgg, Format format) const;

		/**
		* Assignment Operator. The usint val will be set at index zero and all other indices will be set to zero.
        *
        * @param val is the usint to assign to index zero.
        * @return the resulting vector.
        */
		const ILVector2n& operator=(usint val);

		virtual ~ILVector2n();

		/**
		* Equal operator compares this ILVector2n to the specified ILVector2n
		*
		* @param &rhs is the specified ILVector2n to be compared with this ILVector2n.
		* @return true if this ILVector2n represents the same values as the specified ILVectorArray2n, false otherwise
		*/
        inline bool operator==(const ILVector2n &rhs) const {
            if (this->GetFormat() != rhs.GetFormat()) {
                return false;
            }
            if(m_params.GetRootOfUnity() != rhs.GetRootOfUnity())
            	return false;
            if (this->GetValues() != rhs.GetValues()) {
                return false;
            }
            return true;
        }
		/**
		* Not equal operator compares this ILVector2n to the specified ILVectorArray2n
		*
		* @param &element is the specified ILVector2n to be compared with this ILVectorArray2n.
		* @return true if this ILVector2n represents the same values as the specified ILVector2n, false otherwise
		*/
        inline bool operator!=(const ILVector2n &element) const {
            return !(*this == element);
        }

        //GETTERS
		/**
		* Get method to get ILParams for the current vector.
		*
		* @return the ring element params.
		*/
		inline const ILParams &GetParams() const { return m_params; }

		/**
		* Get method of the modulus.
		*
		* @return the modulus.
		*/
		const BigBinaryInteger &GetModulus() const;

		/**
		* Get method for cyclotomic order.
		*
		* @return the cyclotomic order.
		*/
		const usint GetCyclotomicOrder() const;

		/**
		* Get method of the vector.
		*
		* @return the vector.
		*/
		const BigBinaryVector &GetValues() const;

		/**
		* Get method of the root of unity.
		*
		* @return the root of unity.
		*/
		const BigBinaryInteger &GetRootOfUnity() const;

		/**
		* Get method of the format.
		*
		* @return the format.
		*/
		Format GetFormat() const;

		/**
		* Get value of binaryvector at index i.
		*
		* @return value at index i.
		*/
		const BigBinaryInteger& GetValAtIndex(usint i) const;

		/**
		* Get method of the length of the element.
		*
		* @return the length of the element.
		*/
		usint GetLength() const;

		//SETTERS
		/**
		* Set method of the values.
		*
		* @param values is the set of values of the vector.
		* @param format is the format.
		*/
		void SetValues(const BigBinaryVector& values, Format format);

		/**
		* Sets all values to zero.
		*/
		void SetValuesToZero();

		/**
		* Sets the format.
		*
		* @param format is the Format to be set.
		*/
		void SetFormat(const Format format);

		/**
        *  Set BigBinaryVector value to val
        *
        * @param index is the index at which the value is to be set.
		* @param val is the value to be set.
        */
        inline void SetValAtIndex(size_t index, int val) {
            m_values->SetValAtIndex(index, BigBinaryInteger(val));
        }

		// SCALAR OPERATIONS
        /**
		* Performs an subtracion operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		inline const ILVector2n& operator+=(const BigBinaryInteger &element) {
            ILVector2n result = this->Plus(element);
            *this = result;
            return *this;
        }

		/**
		* Performs an subtracion operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		inline const ILVector2n& operator-=(const BigBinaryInteger &element) {
            ILVector2n result = this->Minus(element);
            *this = result;
            return *this;
        }

        /**
		* Performs an multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		inline const ILVector2n& operator*=(const BigBinaryInteger &element) {
            ILVector2n result = this->Times(element);
            *this = result;
            return *this;
        }

		/**
		* Scalar addition - add an element to the first index only. 
		* This operation is only allowed in COEFFICIENT format.
		*
		* @param &element is the element to add entry-wise.
		* @return is the return of the addition operation.
		*/
		ILVector2n Plus(const BigBinaryInteger &element) const;

		/**
		* Scalar subtraction - subtract an element to all entries.
		*
		* @param &element is the element to subtract entry-wise.
		* @return is the return value of the minus operation.
		*/
		ILVector2n Minus(const BigBinaryInteger &element) const;

		/**
		* Scalar multiplication - multiply all entries.
		*
		* @param &element is the element to multiply entry-wise.
		* @return is the return value of the times operation.
		*/
		ILVector2n Times(const BigBinaryInteger &element) const;

		// VECTOR OPERATIONS
		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		ILVector2n Plus(const ILVector2n &element) const;

		/**
		* Performs a subtraction operation and returns the result.
		*
		* @param &element is the element to subtract with.
		* @return is the result of the subtraction.
		*/
		ILVector2n Minus(const ILVector2n &element) const;

		/**
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		ILVector2n Times(const ILVector2n &element) const;

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVector2n& operator+=(const ILVector2n &element);

		/**
		* Performs an subtracion operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
        const ILVector2n& operator-=(const ILVector2n &element);

		/**
		* Performs an multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		const ILVector2n& operator*=(const ILVector2n &element);

		// OTHER METHODS

		/**
		* Adds one to every entry of the ILVector2n.
		*/
		void AddILElementOne();

		/**
		* Performs an automorphism transform operation and returns the result.
		*
		* @param &i is the element to perform the automorphism transform with.
		* @return is the result of the automorphism transform.
		*/
		ILVector2n AutomorphismTransform(const usint &i) const;

		/**
		* Performs a multiplicative inverse operation and returns the result.
		*
		* @return is the result of the multiplicative inverse.
		*/
		ILVector2n MultiplicativeInverse() const;

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return is the return value of the modulus by 2, also the least significant bit.
		*/
		ILVector2n ModByTwo() const;

		/**
		* Modulus - perform a modulus operation. Does proper mapping of [-modulus/2, modulus/2) to [0, modulus)
		*
		* @param modulus is the modulus to use.
		* @return is the return value of the modulus.
		*/
		ILVector2n SignedMod(const BigBinaryInteger &modulus) const;

		/**
		* Switch modulus and adjust the values
		*
		* @param &modulus is the modulus to be set.
		* @param &rootOfUnity is the corresponding root of unity for the modulus
		* ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus.
		*/
		void SwitchModulus(const BigBinaryInteger &modulus, const BigBinaryInteger &rootOfUnity);

		/**
		* Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
		*/
		void SwitchFormat();

		/**
		* Prints values of the ILVector2n.
		*/
		void PrintValues() const;

		/**
		* Make ILVectorArray2n Sparse for SHE KeyGen operations. Sets every index not equal to zero mod the wFactor to zero.
		*
		* @param &wFactor ratio between the original ILVectorArray2n's ring dimension and the new ring dimension.
		*/
		void MakeSparse(const BigBinaryInteger &wFactor);

		/**
		* Interleaves values in the ILVector2n with odd indices being all zeros.
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
		ILVector2n Round(const BigBinaryInteger& x) const;

		// get digit for a specific based - used for PRE scheme
		/**
		* Get digit for a specific base.  Gets a binary polynomial from a given polynomial.  From every coefficient, it extracts the same digit.  Used in bit decomposition/relinearization operations.
		*
		* @param index is the index to get.
		* @param base is the base the result should be in.
		* @return is the result.
		*/
		ILVector2n GetDigitAtIndexForBase(usint index, usint base) const;

		/**
		* Write vector x (current value of the ILVector2n object) as \sum\limits{i=0}^{\lfloor {\log q/base} \rfloor} {(base^i u_i)} and 
		* return the vector of {u_0, u_1,...,u_{\lfloor {\log q/base} \rfloor}} \in R_base^{\lceil {\log q/base} \rceil};
		* used as a subroutine in the relinearization procedure
		*
		* @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
		* @result is the pointer where the base decomposition vector is stored
		*/
		void BaseDecompose(usint baseBits, std::vector<ILVector2n> *result) const;

		/**
		* Generate a vector of ILVector2n's as {x, base*x, base^2*x, ..., base^{\lfloor {\log q/base} \rfloor}*x, where x is the current ILVector2n object;
		* used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element
		*
		* @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
		* @result is the pointer where the base decomposition vector is stored
		*/
		std::vector<ILVector2n> PowersOfBase(usint baseBits) const;

		/**
		* Shift entries in the vector left a specific number of entries.
		*
		* @param n the number of entries to shift left.
		* @return is the resulting vector from shifting left.
		*/
		ILVector2n ShiftLeft(unsigned int n) const;

		/**
		* Shift entries in the vector right a specific number of entries.
		*
		* @param n the number of entries to shift right.
		* @return is the resulting vector from shifting right.
		*/
		ILVector2n ShiftRight(unsigned int n) const;

		/**
		* Print the pre-computed discrete Gaussian samples.
		*/
		static void PrintPreComputedSamples() {
			for (usint i = 0; i < SAMPLE_SIZE; i++)
				std::cout << m_dggSamples[i].GetValues() << std::endl;
		}

		/**
		* Pre computes the Dgg samples.
		*
		* @param &dgg the discrete Gaussian Generator.
		* @param &params are the relevant ring parameters.
		*/
		static void PreComputeDggSamples(const DiscreteGaussianGenerator &dgg, const ILParams &params);

		/**
		* Clear the pre-computed discrete Gaussian samples.
		*/
		static void DestroyPreComputedSamples() {
			m_dggSamples.clear();
		}

		//JSON FACILITY
		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized* serObj, const std::string fileFlag = "") const;

		/**
		* Populate the object from the deserialization of the Setialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj);

	private:

		// stores either coefficient or evaluation representation
		BigBinaryVector *m_values;

		// 1 for coefficient and 0 for evaluation format
		Format m_format;

		// noise norm associated with this vector - to be defined later
		// BigBinaryInteger m_norm;

		// reference to the parameters for ideal lattices
		ILParams m_params;

		// static variables to store pre-computed samples and the parms that went with them
		static std::vector<ILVector2n> m_dggSamples;
		static ILParams m_dggSamples_params;


		// static variable to store the sample size for each set of ILParams
		static const usint m_sampleSize = SAMPLE_SIZE;

		bool m_empty;

		// gets a random discrete Gaussian polynomial
		static const ILVector2n GetPrecomputedVector(const ILParams &params);
	};

	// overloaded operators for ILVector2n

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline ILVector2n operator+(const ILVector2n &a, const BigBinaryInteger &b) { return a.Plus(b); }

	/**
	* Subtraction operator overload.  Performs a subtraction in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction in the ring.
	*/
	inline ILVector2n operator-(const ILVector2n &a, const BigBinaryInteger &b) { return a.Minus(b); }
	//PREV1

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline ILVector2n operator*(const BigBinaryInteger &b, const ILVector2n &a) { return a.Times(b); }

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline ILVector2n operator+(const ILVector2n &a, const ILVector2n &b) { return a.Plus(b); }

	/**
	* Subtraction operator overload.  Performs a subtraction in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction in the ring.
	*/
	inline ILVector2n operator-(const ILVector2n &a, const ILVector2n &b) { return a.Minus(b); }

	//PREV1

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline ILVector2n operator*(const ILVector2n &a, const ILVector2n &b) { return a.Times(b); }

    inline std::ostream& operator<<(std::ostream& os, const ILVector2n& vec){
        os << vec.GetValues();
        return os;
    }

} // namespace lbcrypto ends

#endif
