#include "../lib/math/transfrm.h"

using namespace lbcrypto;

int main() {
	
	std::vector<std::complex<double>> dftVec(64);
	dftVec.at(0) = std::complex<double>(4, 0);
	dftVec.at(1) = std::complex<double>(5, 0);
	dftVec.at(2) = std::complex<double>(5, 0);
	dftVec.at(3) = std::complex<double>(4.2, 0);
	dftVec.at(4) = std::complex<double>(5, 0);
	dftVec.at(5) = std::complex<double>(7.1, 0);
	dftVec.at(6) = std::complex<double>(6, 0);
	dftVec.at(7) = std::complex<double>(3, 0);
	dftVec.at(8) = std::complex<double>(4, 0);
	dftVec.at(9) = std::complex<double>(5, 0);
	dftVec.at(10) = std::complex<double>(5, 0);
	dftVec.at(11) = std::complex<double>(4.2, 0);
	dftVec.at(12) = std::complex<double>(5, 0);
	dftVec.at(13) = std::complex<double>(7.1, 0);
	dftVec.at(14) = std::complex<double>(6, 0);
	dftVec.at(15) = std::complex<double>(3, 0);
	dftVec.at(16) = std::complex<double>(4, 0);
	dftVec.at(17) = std::complex<double>(5, 0);
	dftVec.at(18) = std::complex<double>(5, 0);
	dftVec.at(19) = std::complex<double>(4.2, 0);
	dftVec.at(20) = std::complex<double>(5, 0);
	dftVec.at(21) = std::complex<double>(7.1, 0);
	dftVec.at(22) = std::complex<double>(6, 0);
	dftVec.at(23) = std::complex<double>(3, 0);
	dftVec.at(24) = std::complex<double>(4, 0);
	dftVec.at(25) = std::complex<double>(5, 0);
	dftVec.at(26) = std::complex<double>(5, 0);
	dftVec.at(27) = std::complex<double>(4.2, 0);
	dftVec.at(28) = std::complex<double>(5, 0);
	dftVec.at(29) = std::complex<double>(7.1, 0);
	dftVec.at(30) = std::complex<double>(6, 0);
	dftVec.at(31) = std::complex<double>(3, 0);
	dftVec.at(32) = std::complex<double>(4, 0);
	dftVec.at(33) = std::complex<double>(5, 0);
	dftVec.at(34) = std::complex<double>(5, 0);
	dftVec.at(35) = std::complex<double>(4.2, 0);
	dftVec.at(36) = std::complex<double>(5, 0);
	dftVec.at(37) = std::complex<double>(7.1, 0);
	dftVec.at(38) = std::complex<double>(6, 0);
	dftVec.at(39) = std::complex<double>(3, 0);
	dftVec.at(40) = std::complex<double>(4, 0);
	dftVec.at(41) = std::complex<double>(5, 0);
	dftVec.at(42) = std::complex<double>(5, 0);
	dftVec.at(43) = std::complex<double>(4.2, 0);
	dftVec.at(44) = std::complex<double>(5, 0);
	dftVec.at(45) = std::complex<double>(7.1, 0);
	dftVec.at(46) = std::complex<double>(6, 0);
	dftVec.at(47) = std::complex<double>(3, 0);
	dftVec.at(48) = std::complex<double>(4, 0);
	dftVec.at(49) = std::complex<double>(5, 0);
	dftVec.at(50) = std::complex<double>(5, 0);
	dftVec.at(51) = std::complex<double>(4.2, 0);
	dftVec.at(52) = std::complex<double>(5, 0);
	dftVec.at(53) = std::complex<double>(7.1, 0);
	dftVec.at(54) = std::complex<double>(6, 0);
	dftVec.at(55) = std::complex<double>(3, 0);
	dftVec.at(56) = std::complex<double>(4, 0);
	dftVec.at(57) = std::complex<double>(5, 0);
	dftVec.at(58) = std::complex<double>(5, 0);
	dftVec.at(59) = std::complex<double>(4.2, 0);
	dftVec.at(60) = std::complex<double>(5, 0);
	dftVec.at(61) = std::complex<double>(7.1, 0);
	dftVec.at(62) = std::complex<double>(6, 0);
	dftVec.at(63) = std::complex<double>(3, 0);
	

	DiscreteFourierTransform::GetInstance().PreComputeTable(128);

	double start = currentDateTime();
	std::vector<std::complex<double>> dftVec2 = DiscreteFourierTransform::GetInstance().ForwardTransform(dftVec);
	double end = currentDateTime();
	std::cout << "Without table: " << end - start << " ms" << std::endl;

	start = currentDateTime();
	std::vector<std::complex<double>> dftVec3 = DiscreteFourierTransform::GetInstance().ForwardTransformAlt(dftVec);
	end = currentDateTime();
	std::cout << "With table: " << end - start << " ms" << std::endl<<std::endl;

	std::cin.ignore();
	std::cin.get();
}