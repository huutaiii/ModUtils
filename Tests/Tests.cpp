#include "pch.h"
#include "CppUnitTest.h"

#include <MathUtils.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace Tests
{
	TEST_CLASS(TestsMathUtils)
	{
	public:
		
		TEST_METHOD(Testabsclamp)
		{
			Assert::AreEqual(absclamp(1.f, 2.f, 3.f), 2.f);
			Assert::AreEqual(absclamp(-1.f, 2.f, 3.f), -2.f);
			Assert::AreEqual(absclamp(5.f, 2.f, 3.f), 3.f);
			Assert::AreEqual(absclamp(-5.f, 2.f, 3.f), -3.f);
		}

		TEST_METHOD(TestTemplateSafediv)
		{
			Assert::IsTrue(safediv(glm::vec2(1.f, 1.f), 2.f) == glm::vec2(1.f / 2.f, 1.f / 2.f));
			Assert::IsTrue(safediv(glm::vec3(1.f), 2.f) == glm::vec3(1.f / 2.f));
		}

	};
}
