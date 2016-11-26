#ifndef _SRC_LIB_LATTICE_SIGNATURE_FIELD2N_H
#define _SRC_LIB_LATTICE_SIGNATURE_FIELD2N_H

#include "ilvector2n.h"
#include "../math/transfrm.h"

namespace lbcrypto {

	class Field2n :public std::vector<std::complex<double>> {
	public:
		Field2n() : format(COEFFICIENT) {};
		Field2n(int size, Format f = EVALUATION, bool initializeElementToZero = false)
			:std::vector<std::complex<double>>(size, initializeElementToZero ? 0 : -DBL_MAX) {

			this->format = f;
		}
		Field2n(const ILVector2n & element) {
			if (element.GetFormat() != COEFFICIENT) {
				throw std::logic_error("ILVector2n not in coefficient representation");
			}
			else {
				for (int i = 0;i < element.GetLength();i++) {
					this->push_back(element.GetValAtIndex(i).ConvertToDouble());
					this->format = COEFFICIENT;
				}
			}
		}
		Field2n(const Matrix<int32_t> &element) {
			for (int i = 0;i < element.GetCols();i++) {
				this->push_back(element(0, i));
			}
			this->format = COEFFICIENT;
		}
		Format GetFormat() const {
			return format;
		}
		Field2n Inverse() const {
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
		Field2n Plus(const Field2n &rhs) const {
			Field2n sum(this->size(), EVALUATION);
			for (int i = 0;i < this->size(); i++) {
				sum.at(i) = this->at(i) + rhs.at(i);
			}
			return sum;
		};
		Field2n Minus(const Field2n &rhs) const {
			Field2n difference(this->size(), EVALUATION);
			for (int i = 0;i < this->size(); i++) {
				difference.at(i) = this->at(i) - rhs.at(i);
			}
			return difference;
		};
		Field2n Times(const Field2n & rhs) const {
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
		Field2n ShiftRight() {
			if (this->format == COEFFICIENT) {
				Field2n result(this->size(), COEFFICIENT);
				for (int i = 0;i < this->size() - 1;i++) {
					result.at(i + 1) = this->at(i);
				}
				result.at(this->size() - 1) = std::complex<double>(-1, 0) * this->at(this->size() - 1);
				return result;
			}
			else {
				throw std::logic_error("Polynomial not in coefficient representation");
			}
		}
		Field2n Transpose() const {
			if (this->format == COEFFICIENT) {
				Field2n transpose(this->size(), COEFFICIENT);
				for (int i = this->size() - 1;i > 0;i--) {
					transpose.at(this->size() - 1 - i) = std::complex<double>(-1, 0) * this->at(i);
				}
				transpose.at(0) = this->at(0);
				return transpose;
			}
			else {
				throw std::logic_error("Polynomial not in coefficient representation");
			}
		}
		Field2n ExtractOdd() const {
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
		Field2n ExtractEven() const {
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
		Field2n Permute() const {
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
		Field2n InversePermute() {
			if (this->format == COEFFICIENT) {
				Field2n invpermuted(this->size(), COEFFICIENT, true);
				int evenPtr = 0;
				int oddPtr = this->size() / 2;
				for (int i = 0;evenPtr < 4;i += 2) {
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
		Field2n ScalarMult(double d) {
			Field2n scaled(this->size(), this->GetFormat(), true);
			for (int i = 0;i < this->size();i++) {
				scaled.at(i) = d * this->at(i);
			}
			return scaled;
		}
		void SwitchFormat() {
			if (format == COEFFICIENT) {
				DiscreteFourierTransform dft;

				std::vector<std::complex<double>> r = dft.ForwardTransform(*this);
				for (int i = 0;i < r.size();i++) {
					this->at(i) = r.at(i);
				}

				format = EVALUATION;
			}
			else {
				if (format == COEFFICIENT) {
					DiscreteFourierTransform dft;
					std::vector<std::complex<double>> r = dft.InverseTransform(*this);
					for (int i = 0;i < r.size();i++) {
						this->at(i) = r.at(i);
					}
					format = COEFFICIENT;
				}
			}
		}
		size_t Size() const {
			return this->size();
		}
		inline std::complex<double>& operator[](std::size_t idx) { return (this->at(idx)); }
		inline const std::complex<double>& operator[](std::size_t idx) const { return (this->at(idx)); }
	private:
		Format format;
	};
	inline Field2n operator+(const Field2n &a, const Field2n &b) { return a.Plus(b); }
	inline Field2n operator-(const Field2n &a, const Field2n &b) { return a.Minus(b); }
	inline Field2n operator*(const Field2n &a, const Field2n &b) { return a.Times(b); }
}
#endif