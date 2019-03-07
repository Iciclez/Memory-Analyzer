#include "aobscan.hpp"
#include <functional>
#include <algorithm>
#include <sstream>

aobscan::aobscan(const std::string & pattern, void *memory_start, size_t memory_size, uint32_t result)
	: pattern(pattern), memory_start(memory_start), memory_size(memory_size), result(result)
{
	std::function<void(std::string &, const std::string &, const std::string &)> replace =
		[](std::string &string_to_replace, const std::string &from, const std::string &to)
	{
		for (size_t n = 0; (n = string_to_replace.find(from, n)) != std::string::npos; n += to.size() - 1)
		{
			string_to_replace.replace(n, from.size(), to);
		}
	};

	replace(this->pattern, " ? ", " ?? ");
	this->pattern.erase(std::find_if(this->pattern.rbegin(), this->pattern.rend(), [](int32_t c) { return c != ' ' && c != '?'; }).base(), this->pattern.end());
	this->pattern.erase(std::remove(this->pattern.begin(), this->pattern.end(), ' '), this->pattern.end());

	if (this->pattern.empty() || this->pattern.size() % 2)
	{
		return;
	}

	this->pattern_size = static_cast<size_t>(this->pattern.size() / 2);
	this->bytearray.reserve(pattern_size);
	this->mask.reserve(pattern_size);

	std::stringstream stream;
	for (size_t n = 0; n < this->pattern.size(); n += 2)
	{
		if (this->pattern.at(n) == '?' && this->pattern.at(n + 1) == '?')
		{
			this->mask.push_back(1);
			this->bytearray.push_back(0);
		}
		else
		{
			this->mask.push_back(0);

			stream.str("");
			stream << std::hex << this->pattern.at(n) << this->pattern.at(n + 1);
			this->bytearray.push_back(std::stoi(stream.str(), nullptr, 16));
		}
	}
}

aobscan::~aobscan() noexcept
{
}

const std::vector<uint8_t>& aobscan::get_bytearray()
{
	return this->bytearray;
}

const std::vector<uint8_t>& aobscan::get_mask()
{
	return this->mask;
}

const std::string & aobscan::get_pattern()
{
	return this->pattern;
}
