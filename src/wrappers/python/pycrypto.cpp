//PYTHON WRAPPER
#define BOOST_PYTHON_STATIC_LIB //needed for Windows

#include <boost/python.hpp>

#include "conjinterface.h"
#include "glminterface.h"

using namespace std;
using namespace boost::python;

template <typename T> class cppVectorToPythonList {

public:

	static PyObject* convert(const vector<T>& vector) {

		boost::python::list* pythonList = new boost::python::list();

		for (unsigned int i = 0; i < vector.size(); i++) {
			pythonList->append(vector[i]);
		}

		return pythonList->ptr();
	}
};

BOOST_PYTHON_MODULE(pycrypto) {

	// Whenever a vector<int> is returned by a function, it will automatically be converted to a Python list.
	to_python_converter<vector<uint64_t>, cppVectorToPythonList<uint64_t> >();
	to_python_converter<vector<double>, cppVectorToPythonList<double> >();

    // no_init tells boost.python that Ciphertext's constructor shouldn't be accessed by the Python interface.
    // Whenever a pointer is returned, a return_value_policy<manage_new_object>() is specified to tell Python that it should
    // take responsibility over the object and delete it when not used anymore (to avoid memory leaks). If no return_value_policy
    // is specified, a compilation error will occur.
    // staticmethod is important to specify when a static method is involved, or else a compilation error will occur.
	class_<pycrypto::Obfuscator >("Obfuscator")
		.def("Initialize", &pycrypto::Obfuscator::Initialize)
		.def("Evaluate", &pycrypto::Obfuscator::Evaluate)
		.def("EvaluateClear", &pycrypto::Obfuscator::EvaluateClear);

	class_<glmcrypto::GLMClient >("GLMClient")
			.def("KeyGen", &glmcrypto::GLMClient::KeyGen)
			.def("Encrypt", &glmcrypto::GLMClient::Encrypt)
			.def("SetGLMParams", &glmcrypto::GLMClient::SetGLMParams)
			.def("SetFileNamesPaths", &glmcrypto::GLMClient::SetFileNamesPaths)
			.def("ComputeError", &glmcrypto::GLMClient::ComputeError)
			.def("Step1ComputeLink", &glmcrypto::GLMClient::Step1ComputeLink)
			.def("Step2RescaleC1", &glmcrypto::GLMClient::Step2RescaleC1)
			.def("Step3RescaleRegressor", &glmcrypto::GLMClient::Step3RescaleRegressor, return_value_policy<return_by_value>())
			.def("PrintTimings", &glmcrypto::GLMClient::PrintTimings);

	class_<glmcrypto::GLMServer >("GLMServer")
			.def("SetGLMContext", &glmcrypto::GLMServer::SetGLMContext)
			.def("SetGLMParams", &glmcrypto::GLMServer::SetGLMParams)
			.def("SetFileNamesPaths", &glmcrypto::GLMServer::SetFileNamesPaths)
			.def("Step1ComputeXW", &glmcrypto::GLMServer::Step1ComputeXW)
			.def("Step2ComputeXTSX", &glmcrypto::GLMServer::Step2ComputeXTSX)
			.def("Step3ComputeRegressor", &glmcrypto::GLMServer::Step3ComputeRegressor)
			.def("PrintTimings", &glmcrypto::GLMServer::PrintTimings);

}






