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
//#include "../encoding/ptxtencoding.h"

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
        ILVector2n(const ElemParams &params, Format format = EVALUATION);

        /**
         *  Set BigBinaryVector value to val
         */
        inline void SetValAtIndex(size_t index, int val) {
            m_values->SetValAtIndex(index, BigBinaryInteger(val));
        }


        /**
         *  Get BigBinaryVector value at index
         */
        //double GetValAtIndex(size_t index) {
        //    m_values->GetValAtIndex(index);
        //}

        ///**
        // *  Set to the constant polynomial 1.
        // */
        //inline void SetIdentity() {
        //    *this = ILVector2n(*this);
        //    this->SetValAtIndex(0, 1);
        //    for (size_t i = 1; i < m_values->GetLength(); ++i) {
        //        this->SetValAtIndex(i, 0);
        //    }
        //}

/*
        BigBinaryInteger& Norm() {
            BigBinaryInteger& norm = 0;
	    BigBinaryInteger& norm_t;
            for (size_t i = 0; i < m_values->GetLength(); ++i) {
                norm_t = this->GetValAtIndex(i);
		if (norm_t > norm) {
			norm = norm_t;
		}
            }
            return norm;
        }
*/

        /**
         *  Create lambda that allocates a zeroed element with the specified
         *  parameters and format
         */
        inline static function<unique_ptr<ILVector2n>()> MakeAllocator(ILParams params, Format format) {
            return [=]() {
                return make_unique<ILVector2n>(params, format);
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
                DiscreteGaussianGenerator dgg(params.GetModulus(), stddev);
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
		* Copy constructor.
		*
		* @param &&element the copied element.
		*/
		ILVector2n(ILVector2n &&element);

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		const ILVector2n& operator=(const ILVector2n &rhs);

		/**
		* Assignment Operator.
        *
        * @param &&rhs the copied vector.
        * @return the resulting vector.
        */
        const ILVector2n& operator=(ILVector2n &&rhs);

		/**
		* Assignment Operator. The usint val will be set at index zero and all other indices will be set to zero.
        *
        * @param val is the usint to assign to index zero.
        * @return the resulting vector.
        */
		inline const ILVector2n& operator=(usint val) {
            SetFormat(COEFFICIENT);
            this->SetValAtIndex(0, val);
            for (size_t i = 1; i < m_values->GetLength(); ++i) {
                this->SetValAtIndex(i, 0);
            }
            SetFormat(EVALUATION);
            return *this;
        }

		/**
		* Equal operator compares this ILVector2n to the specified ILVector2n
		*
		* @param &rhs is the specified ILVector2n to be compared with this ILVector2n.
		* @return true if this ILVector2n represents the same values as the specified ILVectorArray2n, false otherwise
		*/
        inline bool operator==(const lbcrypto::ILVector2n &rhs) const {
            if (this->GetFormat() != rhs.GetFormat()) {
                return false;
            }
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
        inline bool operator!=(const lbcrypto::ILVector2n &element) const {
            return !(*this == element);
        }

		/**
		* Performs an subtracion operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
        inline const ILVector2n& operator-=(const lbcrypto::ILVector2n &element) {
            ILVector2n result = this->Minus(element);
            *this = result;
            return *this;
        }

		/**
		* Performs an subtracion operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		inline const ILVector2n& operator+=(const lbcrypto::BigBinaryInteger &element) {
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
		inline const ILVector2n& operator-=(const lbcrypto::BigBinaryInteger &element) {
            ILVector2n result = this->Minus(element);
            *this = result;
            return *this;
        }
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
		* @param &dgg the input discrete Uniform Generator.
		* @param &params the input params.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVector2n(DiscreteUniformGenerator &dgg, const ElemParams &params, Format format = EVALUATION);
		/**
		* Constructor based on full methods.
		*
		* @param &dbg the input Binary Uniform Generator.
		* @param &params the input params.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVector2n(BinaryUniformGenerator &dbg, const ElemParams &params, Format format = EVALUATION);

		/**
		* Destructor.
		*/
		~ILVector2n();

		//void GenerateGaussian(DiscreteGaussianGenerator &dgg);

		/**
		* Get method of the modulus.
		*
		* @return the modulus.
		*/
		const BigBinaryInteger &GetModulus() const;

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
		* Get method of the parameter set.
		*
		* @return the parameter set.
		*/
		const ILParams &GetParams() const;

		/**
		* Access method of the parameter set.
		*
		* @return the parameter set.
		*/
		ILParams& AccessParams();

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

		/**
		* Set method of the values.
		*
		* @param values is the set of values of the vector.
		* @param format is the format.
		*/
		void SetValues(const BigBinaryVector& values, Format format);

		/**
		* Set method of the values.
		*
		* @param &modulus is the modulus to be set.
		*/
		void SetModulus(const BigBinaryInteger &modulus);

		/**
		* Switch modulus and adjust the values
		*
		* @param &modulus is the modulus to be set.
		*/
		void SwitchModulus(const BigBinaryInteger &modulus);

		/**
		* Set method of the values.
		*
		* @param &params is the ILParams.
		*/
		void SetParams(const ElemParams &params);

		/**
		* Set method of the format.
		*
		* @param format of ILVector2n.
		*/
		void SetFormat(const Format format);

		// SCALAR OPERATIONS


		/**
		* Scalar addition - add an element to the first index only.
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

		/**
		* Scalar division - divide an element to all entries.
		*
		* @param &element is the element to divide entry-wise.
		* @return is the return value of the division operation.
		*/
		ILVector2n DividedBy(const BigBinaryInteger &element) const;

		/**
		* Modulus - perform a modulus operation.
		*
		* @param modulus is the modulus to use.
		* @return is the return value of the modulus.
		*/
		ILVector2n Mod(const BigBinaryInteger & modulus) const;

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return is the return value of the modulus by 2, also the least significant bit.
		*/
		ILVector2n ModByTwo() const;

		/**
		Print values and don't flush before and don't print new line.
		Set to Test value
		*/
//		void SetToTestValue() ;

		/**
		* Prints values of each tower
		*/
		void PrintValues() const;

		/**
		* Adds one to every entry in every tower.
		*/
		void AddILElementOne();

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

		// VECTOR OPERATIONS

		/**
		* Determines if two vectors are equal.
		*
		* @param &element is the element to test equality with.
		* @return is the Boolean representation of equality.
		*/
		bool Equal(const ILVector2n &element) const;

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

		// addition operation - PREV1
		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		ILVector2n Plus(const ILVector2n &element) const;

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVector2n& operator+=(const ILVector2n &element);

		// subtraction operation
		/**
		* Performs a subtraction operation and returns the result.
		*
		* @param &element is the element to subtract with.
		* @return is the result of the subtraction.
		*/
		ILVector2n Minus(const ILVector2n &element) const;

		// multiplication operation - PREV1
		/**
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		ILVector2n Times(const ILVector2n &element) const;

		// division operation
		/**
		* Performs a division operation and returns the result.
		*
		* @param &element is the element to divide with.
		* @return is the result of the division.
		*/
		ILVector2n DividedBy(const ILVector2n &element) const;

		// automorphism operation
		/**
		* Performs an automorphism transform operation and returns the result.
		*
		* @param &i is the element to perform the automorphism transform with.
		* @return is the result of the automorphism transform.
		*/
		ILVector2n AutomorphismTransform(const usint &i) const;

		// multiplicative inverse operation
		/**
		* Performs a multiplicative inverse operation and returns the result.
		*
		* @return is the result of the multiplicative inverse.
		*/
		ILVector2n MultiplicativeInverse() const;

		// OTHER METHODS

		// rounds polynomial to a certain integer x
		/**
		* Rounds the polynomial to an input integer.
		*
		* @param x is integer to round to.
		* @return is the result of the rounding operation.
		*/
		ILVector2n Round(const BigBinaryInteger& x) const;

		// convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT
		/**
		* Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
		*/
		void SwitchFormat();

        

		// get digit for a specific based - used for PRE scheme
		/**
		* Get digit for a specific base.  Gets a binary polynomial from a given polynomial.  From every coefficient, it extracts the same digit.  Used in bit decomposition/relinearization operations.
		*
		* @param index is the index to get.
		* @param base is the base the result should be in.
		* @return is the result.
		*/
		ILVector2n GetDigitAtIndexForBase(usint index, usint base) const;

		// does the vector have any coefficients
		/**
		* Returns whether the vector is all zero.
		*
		* @return returns whether the vector is all zero.
		*/
		bool IsZero() const;

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

		// computes the samples
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
		* Implemented by this object only for inheritance requirements of abstract class Serializable.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @param flag TODO.
		* @return map passed in.
		*/
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

		//JSON FACILITY
		/**
		* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
		* Invokes nested serialization of BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @param fileFlag TODO.
		* @return map updated with the attribute name value pairs required to serialize this object.
		*/
		std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const;

		//JSON FACILITY
		/**
		* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
		* Invokes nested deserialization of BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		*/
		void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap);

	private:

		// stores either coefficient or evaluation representation
		BigBinaryVector *m_values;

		//TODO-nishanth: Isn't it 1 for coefficient and 0 for evaluation ??
		// 0 for coefficient and 1 for evaluation format
		Format m_format;

		// noise norm associated with this vector - to be defined later
		// BigBinaryInteger m_norm;

		// reference to the parameters for ideal lattices
		ILParams m_params;

		// static variable to store pre-computed samples
		static std::vector<ILVector2n> m_dggSamples;

		// static variable to store the sample size for each set of ILParams
		static const usint m_sampleSize = SAMPLE_SIZE;

		// gets a random discrete Gaussian polynomial
		const ILVector2n GetPrecomputedVector(const ILParams &params);

	};

	// overloaded operators for ILVector2n
	//PREV1

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline lbcrypto::ILVector2n operator+(const lbcrypto::ILVector2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Plus(b); }

	/**
	* Subtraction operator overload.  Performs a subtraction in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction in the ring.
	*/
	inline lbcrypto::ILVector2n operator-(const lbcrypto::ILVector2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Minus(b); }
	//PREV1

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVector2n operator*(const lbcrypto::BigBinaryInteger &b, const lbcrypto::ILVector2n &a) { return a.Times(b); }

	/**
	* Division operator overload.  Performs an division in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of division in the ring.
	*/
	inline lbcrypto::ILVector2n operator/(const lbcrypto::ILVector2n &a, const lbcrypto::BigBinaryInteger &b) { return a.DividedBy(b); }
	//PREV1

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline lbcrypto::ILVector2n operator+(const lbcrypto::ILVector2n &a, const lbcrypto::ILVector2n &b) { return a.Plus(b); }

	/**
	* Subtraction operator overload.  Performs a subtraction in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction in the ring.
	*/
	inline lbcrypto::ILVector2n operator-(const lbcrypto::ILVector2n &a, const lbcrypto::ILVector2n &b) { return a.Minus(b); }

	//PREV1

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVector2n operator*(const lbcrypto::ILVector2n &a, const lbcrypto::ILVector2n &b) { return a.Times(b); }

	/**
	* Division operator overload.  Performs an division in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of division in the ring.
	*/
	inline lbcrypto::ILVector2n operator/(const lbcrypto::ILVector2n &a, const lbcrypto::ILVector2n &b) { return a.DividedBy(b); }


    inline std::ostream& operator<<(std::ostream& os, const ILVector2n& vec){
        os << vec.GetValues();
        return os;
    }

} // namespace lbcrypto ends

#endif
