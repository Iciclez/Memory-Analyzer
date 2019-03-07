#pragma once
#include <windows.h>
#include <string>
#include <vector>

class aobscan
{
public:
	aobscan(const std::string &pattern, void *memory_start = 0, size_t memory_size = 0, uint32_t result = 1);
	~aobscan() noexcept;

	const std::vector<uint8_t> &get_bytearray();
	const std::vector<uint8_t> &get_mask();
	const std::string &get_pattern();

	//qword or dword
	template <typename T> T address();

private:
	std::vector<uint8_t> bytearray;
	std::vector<uint8_t> mask;
	std::string pattern;

	void *memory_start;
	size_t memory_size;
	uint32_t result;
	size_t pattern_size;
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
				(this->mask.at(j) == 0x01 || !(*reinterpret_cast<uint8_t*>(i + j) ^ bytearray.at(j))))
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
