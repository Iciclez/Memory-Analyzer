#include "aobscan.hpp"


aobscan::aobscan(const std::string & pattern, void *memory_start, size_t memory_size, int32_t result)
	: aobscanbase(pattern, memory_start, memory_size, result)
{
}

aobscan::~aobscan() noexcept
{
}
