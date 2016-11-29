#include "field2n.h"

namespace lbcrypto {

	//Constructor from ring element
	Field2n::Field2n(const ILVector2n & element) {
		if (element.GetFormat() != COEFFICIENT) {
			throw std::logic_error("ILVector2n not in coefficient representation");
		}
		else {
			for (int i = 0;i < element.GetLength();i++) {
				this->push_back(element.GetValAtIndex(i).ConvertToDouble());
			}
			this->format = COEFFICIENT;
		}
	}

	//Constructor from a ring element matrix
	Field2n::Field2n(const Matrix<int32_t> &element) {
		for (int i = 0;i < element.GetRows();i++) {
			this->push_back(element(i, 0));
		}
		this->format = COEFFICIENT;
	}

	//Inverse operation for the field elements
	Field2n Field2n::Inverse() const {
		if (format == COEFFICIENT) {
			throw std::logic_error("Polynomial not in evaluation representation");
		}
		else {
			Field2n inverse(this->size(), EVALUATION);
			for (int i = 0;i < this->size(); i++) {
				double quotient = this->at(i).real() * this->at(i).real() + this->at(i).imag() * this->at(i).imag();
				inverse.at(i) = std::complex<double>(this->at(i).real() / quotient, -this->at(i).imag() / quotient);
			}
			return inverse;
		}
	}

	//Addition operation for field elements
	Field2n Field2n::Plus(const Field2n &rhs) const {
		if (format == rhs.GetFormat()) {
			Field2n sum(this->size(), rhs.GetFormat());
			for (int i = 0;i < this->size(); i++) {
				sum.at(i) = this->at(i) + rhs.at(i);
			}
			return sum;
		}
		else {
			throw std::logic_error("Operands are not in the same format");
		}
	}

	//Substraction operation for field elements
	Field2n Field2n::Minus(const Field2n &rhs) const {
		if (format == rhs.GetFormat()) {
			Field2n difference(this->size(), rhs.GetFormat());
			for (int i = 0;i < this->size(); i++) {
				difference.at(i) = this->at(i) - rhs.at(i);
			}
			return difference;
		}
		else {
			throw std::logic_error("Operands are not in the same format");
		}
	}

	//Multiplication operation for field elements
	Field2n Field2n::Times(const Field2n & rhs) const {
		if (format == EVALUATION && rhs.GetFormat() == EVALUATION) {
			Field2n result(rhs.size(), EVALUATION);
			for (int i = 0;i < rhs.size();i++) {
				result.at(i) = this->at(i) * rhs.at(i);
			}
			return result;
		}
		else {
			throw std::logic_error("At least one of the polynomials is not in evaluation representation");
		}
	}

	//Right shift operation for the field element
	Field2n Field2n::ShiftRight() {
		if (this->format == COEFFICIENT) {
			Field2n result(this->size(), COEFFICIENT);
			std::complex<double> temp = std::complex<double>(-1, 0) * this->at(this->size() - 1);
			for (int i = 0;i < this->size() - 1;i++) {
				result.at(i + 1) = this->at(i);
			}
			result.at(0) = temp;
			return result;
		}
		else {
			throw std::logic_error("Polynomial not in coefficient representation");
		}
	}

	//Transpose operation defined in the paper of perturbation sampling
	Field2n Field2n::Transpose() const {
		if (this->format == COEFFICIENT) {
			Field2n transpose(this->size(), COEFFICIENT);
			for (int i = 1;i < this->size();i++) {
				transpose.at(i) = std::complex<double>(-1, 0) * this->at(this->size() - i);
			}
			transpose.at(0) = this->at(0);
			return transpose;
		}
		else {
			throw std::logic_error("Polynomial not in coefficient representation");
		}
	}

	//Function for extracting odd factors of the field element
	Field2n Field2n::ExtractOdd() const {
		if (this->format == COEFFICIENT) {
			Field2n odds(this->size() / 2, COEFFICIENT, true);
			for (int i = 0;i < odds.size();i++) {
				odds.at(i) = this->at(1 + 2 * i);
			}
			return odds;
		}
		else {
			throw std::logic_error("Polynomial not in coefficient representation");
		}
	}

	//Function for extracting even factors of the field element
	Field2n Field2n::ExtractEven() const {
		if (this->format == COEFFICIENT) {
			Field2n evens(this->size() / 2, COEFFICIENT, true);
			for (int i = 0;i < evens.size();i++) {
				evens.at(i) = this->at(0 + 2 * i);
			}
			return evens;
		}
		else {
			throw std::logic_error("Polynomial not in coefficient representation");
		}
	}

	//Permutation operation defined in the paper
	Field2n Field2n::Permute() const {
		if (this->format == COEFFICIENT) {
			Field2n permuted(this->size(), COEFFICIENT, true);
			int evenPtr = 0;
			int oddPtr = this->size() / 2;
			for (int i = 0;i < this->size();i++) {
				if (i % 2 == 0) {
					permuted.at(evenPtr) = this->at(i);
					evenPtr++;
				}
				else {
					permuted.at(oddPtr) = this->at(i);
					oddPtr++;
				}
			}
			return permuted;
		}
		else {
			throw std::logic_error("Polynomial not in coefficient representation");
		}
	}

	//Inverse operation for permutation operation defined in the paper
	Field2n Field2n::InversePermute() {
		if (this->format == COEFFICIENT) {
			Field2n invpermuted(this->size(), COEFFICIENT, true);
			int evenPtr = 0;
			int oddPtr = this->size() / 2;
			for (int i = 0;evenPtr < this->size() / 2;i += 2) {
				invpermuted.at(i) = this->at(evenPtr);
				invpermuted.at(i + 1) = this->at(oddPtr);
				evenPtr++;
				oddPtr++;
			}
			return invpermuted;
		}
		else {
			throw std::logic_error("Polynomial not in coefficient representation");
		}
	}

	//Operation for scalar multiplication
	Field2n Field2n::ScalarMult(double d) {
		Field2n scaled(this->size(), this->GetFormat(), true);
		for (int i = 0;i < this->size();i++) {
			scaled.at(i) = d * this->at(i);
		}
		return scaled;
	}

	//Method for switching format of the field elements
	void Field2n::SwitchFormat() {
		if (format == COEFFICIENT) {
			DiscreteFourierTransform dft;

			std::vector<std::complex<double>> r = dft.ForwardTransform(*this);
			for (int i = 0;i < r.size();i++) {
				this->at(i) = r.at(i);
			}

			format = EVALUATION;
		}
		else {
			DiscreteFourierTransform dft;
			std::vector<std::complex<double>> r = dft.InverseTransform(*this);
			for (int i = 0;i < r.size();i++) {
				this->at(i) = r.at(i);
			}
			format = COEFFICIENT;

		}
	}
}