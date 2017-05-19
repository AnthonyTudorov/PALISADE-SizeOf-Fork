#include "../native_int/binint.h"

#ifdef _MSC_VER
namespace native_int {

UsageMessage::UsageMessage() {
	std::cout << "Warning: Operations on native_int integers may overflow and not be detected in this version of Visual Studio" << std::endl;
}

static UsageMessage PrintUsageMessageAtStart;

}
#endif
