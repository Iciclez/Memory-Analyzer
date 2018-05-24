#pragma once
#include "aobscanbase.hpp"

class aobscan
	: public aobscanbase
{
public:
	explicit aobscan(const std::string &pattern, void *memory_start = 0, size_t memory_size = 0, int32_t result = 1);
	~aobscan() noexcept;

	//qword or dword
	template <typename T> T address();
};

template<typename T>
inline T aobscan::address()
{
	uint32_t k = 1;
	T begin = reinterpret_cast<T>(memory_start);
	T end = begin + memory_size;

	__try
	{
		for (T i = begin; i < end; ++i)
		{
			size_t j = 0;
			while (j < this->pattern_size &&
				//continue if mask at is ?? or byte at address matches bytearray at
				(this->mask.at(j) == 0x01 || !(*reinterpret_cast<byte*>(i + j) ^ bytearray.at(j))))
			{
				++j;
			}

			if (j == this->pattern_size)
			{
				if (k == this->result)
				{
					return i;
				}

				++k;
			}
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}
