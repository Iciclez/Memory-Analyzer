#pragma once
#include <windows.h>
#include <string>
#include <vector>

class aobscanbase
{
public:
	aobscanbase(const std::string &pattern, void *memory_start = 0, size_t memory_size = 0, uint32_t result = 1);
	~aobscanbase() noexcept;

	const std::vector<byte> &get_bytearray();
	const std::vector<byte> &get_mask();
	const std::string &get_pattern();

protected:
	std::vector<byte> bytearray;
	std::vector<byte> mask;
	std::string pattern;

	void *memory_start;
	size_t memory_size;
	uint32_t result;
	size_t pattern_size;
};

