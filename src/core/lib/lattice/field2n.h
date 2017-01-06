#ifndef _SRC_LIB_LATTICE_SIGNATURE_FIELD2N_H
#define _SRC_LIB_LATTICE_SIGNATURE_FIELD2N_H

#include "ilvector2n.h"
#include "ilvectorarray2n.h"
#include "../math/transfrm.h"
#include "../math/matrix.h"

namespace lbcrypto {

	class Field2n :public std::vector<std::complex<double>>, public Serializable {
	public:
		/**Default Constructor
		*/
		Field2n() : format(COEFFICIENT) {};

		/**Constructor for field element
		*
		*@param size element size
		*@param f format of the element
		*@param initializeElementToZero flag for initializing values to zero
		*/
		Field2n(int size, Format f = EVALUATION, bool initializeElementToZero = false)
			:std::vector<std::complex<double>>(size, initializeElementToZero ? 0 : -DBL_MAX) {
			this->format = f;
		}

		/**Constructor from ring element
		*
		*@param & element ring element
		*/
		explicit Field2n(const ILVector2n & element);

		/** Constructor from a ring element matrix
		*
		*@param &element ring element matrix
		*/
		explicit Field2n(const Matrix<int32_t> & element);

		/**Method for getting the format of the element
		*
		*@return format of the field element
		*/
		Format GetFormat() const { return format; }

		/**Inverse operation for the field elements
		*
		*@return the inverse field element
		*/
		Field2n Inverse() const;

		/**Addition operation for field elements
		*
		*@param &rhs right hand side element for operation
		*@return result of the operation
		*/
		Field2n Plus(const Field2n &rhs) const;

		/**Scalar addition operation for field elements
		*
		*@param &rhs right hand side element for operation
		*@return result of the operation
		*/
		Field2n Plus(double rhs) const;

		/**Substraction operation for field elements
		*
		*@param &rhs right hand side element for operation
		*@return result of the operation
		*/
		Field2n Minus(const Field2n &rhs) const;

		/**Multiplication operation for field elements
		*
		*@param &rhs right hand side element for operation
		*@return result of the operation
		*/
		Field2n Times(const Field2n & rhs) const;

		/**Right shift operation for the field element
		*
		*@return the shifted field element
		*/
		Field2n ShiftRight();

		/**
		* Performs an automorphism transform operation and returns the result.
		*
		* @param &i is the element to perform the automorphism transform with.
		* @return is the result of the automorphism transform.
		*/
		Field2n AutomorphismTransform(size_t i) const;

		/**Transpose operation defined in the paper of perturbation sampling
		*
		*@return the transpose of the element
		*/
		Field2n Transpose() const;

		/**Function for extracting odd factors of the field element
		*
		*@return the field element with odd parts of the initial element
		*/
		Field2n ExtractOdd() const;

		/**Function for extracting even factors of the field element
		*
		*@return the field element with even parts of the initial element
		*/
		Field2n ExtractEven() const;

		/**Permutation operation defined in the paper
		*
		*@return permuted new field element
		*/
		Field2n Permute() const;

		/**Inverse operation for permutation operation defined in the paper
		*
		*@return non permuted version of the element
		*/
		Field2n InversePermute() const;

		/**Operation for scalar multiplication
		*
		*@param d scalar for multiplication
		*@return the field element with the scalar multiplication
		*/
		Field2n ScalarMult(double d);

		/** Method for switching format of the field elements
		*/
		void SwitchFormat();

		/** Method for getting the size of the element
		*
		*@return the size of the element
		*/
		size_t Size() const { return this->size(); }

		/**Indexing operator for field elements
		*
		*@param idx index of the element
		*@return element at the index
		*/
		inline std::complex<double>& operator[](std::size_t idx) { return (this->at(idx)); }

		/**Indexing operator for field elements
		*
		*@param idx index of the element
		*@return element at the index
		*/
		inline const std::complex<double>& operator[](std::size_t idx) const { return (this->at(idx)); }

		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized* serObj) const { return false; }

		/**
		* Populate the object from the deserialization of the Serialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj) { return false; }

	private:
		//Format of the field element
		Format format;
	};

	/**
	*  Stream output operator
	*
	* @param &os stream
	* @param &m matrix to be outputted
	* @return the chained stream
	*/
	inline std::ostream& operator<<(std::ostream& os, const Field2n& m) {
		os << "[ ";
		for (size_t row = 0; row < m.size(); ++row) {
			os << m.at(row) << " ";
		}
		os << " ]\n";
		return os;
	}

	/**Addition operator for field elements
	*
	*@param &a left hand side field element
	*@param &b right hand side field element
	*@return result of the addition operation
	*/
	inline Field2n operator+(const Field2n &a, const Field2n &b) { return a.Plus(b); }

	/**Scalar addition operator for field elements
	*
	*@param &a left hand side field element
	*@param &b  the scalar to be added
	*@return result of the addition operation
	*/
	inline Field2n operator+(const Field2n &a, double scalar) { return a.Plus(scalar); }

	/**Substraction operator for field elements
	*
	*@param &a left hand side field element
	*@param &b right hand side field element
	*@return result of the substraction operation
	*/
	inline Field2n operator-(const Field2n &a, const Field2n &b) { return a.Minus(b); }

	/**Multiplication operator for field elements
	*
	*@param &a left hand side field element
	*@param &b right hand side field element
	*@return result of the multiplication operation
	*/
	inline Field2n operator*(const Field2n &a, const Field2n &b) { return a.Times(b); }
}
#endif
