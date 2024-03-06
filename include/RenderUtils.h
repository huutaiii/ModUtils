#pragma once

#include <vector>
#include <cstdlib>
#include <cstdint>

#include "MathUtils.h"

// sub-pixel jitter generator for TAA
class UJitterGenerator
{
protected:
	std::vector<glm::vec2> Sequence;
	uint32_t Offset; // index of first sample
	uint32_t Distance; // distance between samples
	uint32_t NumPhases;

	// https://en.wikipedia.org/wiki/Halton_sequence
	inline float HaltonSample(uint32_t index, uint32_t base)
	{
		float f = 1.f;
		float r = 0.f;
		for (int i = index; i > 0; i = i / base)
		{
			f = f / base;
			r = r + f * (i % base);
		}
		return r;
	}

	inline void Generate()
	{
		for (int i = 0; i < NumPhases; ++i)
		{
			float x = HaltonSample(i * Distance + Offset, 2);
			float y = HaltonSample(i * Distance + Offset, 3);
			Sequence[i] = glm::vec2(x, y) - glm::vec2(0.5f);
		}
	}

public:

	inline UJitterGenerator(uint32_t numPhases = 8, uint32_t offset = 1, uint32_t distance = 1)
		: NumPhases(numPhases), Offset(offset), Distance(distance)
	{
		Sequence = std::vector<glm::vec2>(static_cast<std::size_t>(numPhases));
		Generate();
	}

	inline glm::vec2 Get(size_t index) const
	{
		return Sequence[index % NumPhases];
	}

	inline const glm::vec2& operator[](size_t index) const
	{
		return Sequence[index % NumPhases];
	}

	inline const uint32_t GetNumPhases() const { return NumPhases; }

	// calculates a recommended jitter phase count for use with temporal super sampling
	// https://github.com/NVIDIA/DLSS/blob/v3.5.10/doc/DLSS_Programming_Guide_Release.pdf
	inline static uint32_t CalcNumPhasesTSR(float targetHeight, float renderHeight, uint32_t baseCount = 8)
	{
		return glm::roundEven(baseCount * pow2(targetHeight / renderHeight));
	}
};


