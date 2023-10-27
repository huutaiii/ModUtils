#include "pch.h"
#include "CppUnitTest.h"

#define GLM_ENABLE_EXPERIMENTAL
#include <glm/gtx/string_cast.hpp>

#include <MathUtils.h>
#include <INIReader.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace Microsoft
{
	namespace VisualStudio
	{
		namespace CppUnitTestFramework
		{
			template <glm::length_t L, typename T, glm::qualifier Q>
			static inline std::wstring ToString(const glm::vec<L, T, Q>& v)
			{
				std::string str = glm::to_string(v);
				return std::wstring(str.begin(), str.end());
			}
		}
	}
}

namespace Tests
{

	TEST_CLASS(TestsMathUtils)
	{
	public:
		TEST_METHOD(Testabsclamp)
		{
			Assert::AreEqual(2.f, absclamp(1.f, 2.f, 3.f));
			Assert::AreEqual(-2.f, absclamp(-1.f, 2.f, 3.f));
			Assert::AreEqual(3.f, absclamp(5.f, 2.f, 3.f));
			Assert::AreEqual(-3.f, absclamp(-5.f, 2.f, 3.f));
		}

		TEST_METHOD(SmoothStepRange0)
		{
			Assert::AreEqual(1.0f, smoothstep(1.0f, 1.0f, 2.0f, std::numeric_limits<float>::quiet_NaN()));
			Assert::AreEqual(0.0f, smoothstep(1.0f, 1.0f, 0.5f, std::numeric_limits<float>::quiet_NaN()));
			Assert::IsTrue(std::isnan(smoothstep(1.0f, 1.0f, 1.0f, std::numeric_limits<float>::quiet_NaN())));
		}

		TEST_METHOD(TestTemplateSafediv)
		{
			Assert::AreEqual(glm::vec2(1.f / 2.f, 1.f / 2.f), safediv(glm::vec2(1.f, 1.f), 2.f));
			Assert::AreEqual(glm::vec3(1.f / 2.f), safediv(glm::vec3(1.f), 2.f));
		}

	};


	TEST_CLASS(INI)
	{
	public:
		TEST_METHOD(ParseVecNil)
		{
			glm::vec4 out(0);
			Assert::IsTrue(INIReader::ParseVec("no", out));
			Assert::AreEqual(glm::vec4(0), out);
		}
		TEST_METHOD(ParseVecFail)
		{
			glm::vec3 dummy(0);
			Assert::IsFalse(INIReader::ParseVec("1, 2", dummy, false));
		}
		TEST_METHOD(ParseVec2)
		{
			glm::vec2 outv2(0);
			Assert::IsTrue(INIReader::ParseVec("(1, 1)", outv2));
			Assert::AreEqual(glm::vec2(1, 1), outv2);
		}

		TEST_METHOD(ParseVec2Fill)
		{
			glm::vec2 outv2(0);
			Assert::IsTrue(INIReader::ParseVec("(1,", outv2));
			Assert::AreEqual(glm::vec2(1, 0), outv2);
		}

		TEST_METHOD(ParseVec3)
		{
			glm::vec3 outv3(0);
			Assert::IsTrue(INIReader::ParseVec("(1, 1, 1)", outv3));
			Assert::AreEqual(glm::vec3(1, 1, 1), outv3);
		}
	};
}
