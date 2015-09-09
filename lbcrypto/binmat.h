/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 *
 * All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.
 *
 * This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
 *
 * @section DESCRIPTION
 *
 * This file contains the matrix manipulation functionality.
 */

#ifndef LBCRYPTO_BINMAT_H
#define LBCRYPTO_BINMAT_H


#include "inttypes.h"
#include "binint.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

//GENERAL NOTE. YSP. Several methods and data members have been moved from BigBinaryVector
/**
 * @brief Class for matrices of big binary integer values.
 */
class BigBinaryMatrix
{

public:

	/**
	 * Basic constructor.	  	  
	 */
	explicit BigBinaryMatrix();

	/**
	 * Basic constructor for specifying the size of the matrix.
	 *
	 * @param dimension1 is the number of rows.	
	 * @param dimension2 is the number of columns.	  	  
	 */
	explicit BigBinaryMatrix(usint dimension1,usint dimension2);

	/**
	 * Basic constructor for copying a matrix
	 *
	 * @param binaryMatrix is the big binary matrix to be copied.  	  
	 */
	explicit BigBinaryMatrix(const BigBinaryMatrix& binaryMatrix);

	/**
	 * ???
	 *
	 * @param rhs is the big binary matrix to test equality with.  
	 * @return the return value.	  
	 */
	BigBinaryMatrix&  operator=(const BigBinaryMatrix& rhs);

	/**
	 * Destructor.	  
	 */
	~BigBinaryMatrix();

	//ACCESSORS

	//Gyana to change to ostream
	/**
	 * ???
	 *
	 * @param os ???.
	 * @param &ptr_obj ???.
	 * @return the return value.	  
	 */
	friend std::ostream& operator<<(std::ostream& os, const BigBinaryMatrix &ptr_obj);

	/**
	 * Sets a value at an index.
	 *
	 * @param rowindex is the row index to set a value at.
	 * @param columnindex is the column index to set a value at.
	 * @param value is the value to set at the index.
	 */
	void SetValAtIndex(usint rowindex, usint columnindex, const BigBinaryInteger& value);

	/**
	 * Sets a value at an index.
	 *
	 * @param rowindex is the row index to set a value at.
	 * @param columnindex is the column index to set a value at.
	 * @param str is the string representation of the value to set at the index.
	 */
	void SetValAtIndex(usint rowindex, usint columnindex, const std::string& str);

	/**
	 * Sets the vector modulus.
	 *
	 * @param value is the value to set.
	 */
	void SetModulus(const BigBinaryInteger& value);

	/**
	 * Sets the vector modulus.
	 *
	 * @param value is the value to set.
	 */
	void SetModulus(std::string value);

	/**
	 * Gets the vector modulus.
	 *
	 * @return the vector modulus.
	 */
	BigBinaryInteger& GetModulus() const;

	/**
	 * Gets the number of rows in the matrix.
	 *
	 * @return the number of rows.
	 */
	usint GetRowSize() const;

	/**
	 * Gets the number of columns in the matrix.
	 *
	 * @return the number of columns.
	 */
	usint GetColumnSize() const;

	/**
	 * Gets a value at an index.
	 *
	 * @param rowindex is the row index to get a value at.
	 * @param columnindex is the column index to get a value at.
	 * @return is the value at the index.
	 */
	BigBinaryInteger& GetValAtIndex(usint rowindex, usint columnindex) const;
	
	//METHODS
	/**
	 * matrix modulus addition.
	 *
	 * @param &rhs is the matrix to add at all locations.
	 * @return is the result of the modulus addition operation.
	 */
	BigBinaryMatrix& operator+(BigBinaryMatrix &rhs) const;

	/**
	 * matrix modulus subtraction.
	 *
	 * @param &rhs is the matrix to subtract at all locations.
	 * @return is the result of the modulus subtraction operation.
	 */
	BigBinaryMatrix& operator-(BigBinaryMatrix &rhs) const;

	/**
	 * matrix modulus addition.
	 *
	 * @param &rhs is the matrix to add.
	 * @return is the result of the modulus addition operation.
	 */
	BigBinaryMatrix& ModAdd(BigBinaryMatrix &rhs) const;

	/**
	 * matrix modulus subtraction.
	 *
	 * @param &rhs is the matrix to subtract.
	 * @return is the result of the modulus subtraction operation.
	 */
	BigBinaryMatrix& ModSub(BigBinaryMatrix &rhs) const;

	/**
	 * Kronecker product operation.
	 *
	 * @param &rhs is the matrix to perform the Kronecker product with.
	 * @return is the result of the Kronecker product operation.
	 */
	BigBinaryMatrix& KroneckerProduct(BigBinaryMatrix &rhs) const;
	//matrix methods will be defined later

private:
	BigBinaryInteger ***m_data;
	usint m_rows;
	usint m_columns;
	BigBinaryInteger m_modulus;
	bool IndexCheck(usint,usint) const;
};

} // namespace lbcrypto ends

#endif
