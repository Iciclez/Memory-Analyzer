#include "aobscanbase.hpp"
#include <algorithm>
#include <sstream>

aobscanbase::aobscanbase(const std::string & pattern, void *memory_start, size_t memory_size, uint32_t result)
{
	this->pattern = pattern;
	this->memory_start = memory_start;
	this->memory_size = memory_size;
	this->result = result;
	this->pattern_size = 0;

	if (!this->pattern.empty())
	{
		//aob formatter
		std::string search = " ? ";
		std::string replace = " ?? ";

		for (size_t n = 0; (n = this->pattern.find(search, n)) != std::string::npos; n += replace.length() - 1)
		{
			this->pattern.replace(n, search.length(), replace);
		}

		while (this->pattern.at(this->pattern.length() - 1) == ' '
			|| this->pattern.at(this->pattern.length() - 1) == '?')
		{
			this->pattern = this->pattern.substr(0, this->pattern.length() - 1);
		}

		//parse array of bytes
		{
			std::string data(this->pattern);
			data.erase(std::remove(data.begin(), data.end(), ' '), data.end());

			if (!((data.size() % 2) || !data.size()))
			{
				this->pattern_size = data.size() / 2;
				this->bytearray.reserve(pattern_size);
				this->mask.reserve(pattern_size);

				for (size_t i = 0; i < data.size(); i += 2)
				{
					if (data.at(i) == '?' && data.at(i + 1) == '?')
					{
						mask.push_back(1);
						bytearray.push_back(0);
					}
					else
					{
						std::stringstream ss;
						ss << std::hex << data.at(i) << data.at(i + 1);
						mask.push_back(0);
						bytearray.push_back(static_cast<uint8_t>(std::stoi(ss.str(), nullptr, 16)));
					}
				}
			}
		}
	}
	
}

aobscanbase::~aobscanbase() noexcept
{
}

const std::vector<byte>& aobscanbase::get_bytearray()
{
	return this->bytearray;
}

const std::vector<byte>& aobscanbase::get_mask()
{
	return this->mask;
}

const std::string & aobscanbase::get_pattern()
{
	return this->pattern;
}
