#include "assembler.hpp"
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <iomanip>
#include <iterator>

#pragma comment (lib, "keystone.lib")

assembler::assembler(const std::vector<std::string>& instructions, assembler_mode mode, assembler_syntax syntax)
{
	this->instructions = instructions;
	this->mode = mode;
	this->syntax = syntax;

	ks_mode m = KS_MODE_32;

	switch (mode)
	{
	case x86:
		m = KS_MODE_32;
		break;

	case x64:
		m = KS_MODE_64;
		break;
	}

	ks_open(KS_ARCH_X86, m, &handle);

	if (syntax == att)
	{
		ks_option(handle, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
	}
}

assembler::~assembler() noexcept
{
	ks_close(handle);
}

const std::string assembler::byte_to_string(const std::vector<uint8_t>& bytes, const std::string &separator)
{
	std::stringstream ss;
	for (size_t n = 0; n < bytes.size(); ++n)
	{
		if (!separator.compare("\\x"))
		{
			ss << separator << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int32_t>(bytes.at(n));
		}
		else
		{
			ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int32_t>(bytes.at(n));

			if (bytes.size() - 1 != n)
			{
				ss << separator;
			}
		}
		
	}

	return ss.str();
}

const std::vector<uint8_t> assembler::string_to_bytes(const std::string & array_of_bytes)
{
	std::vector<uint8_t> data;
	std::string array_data(array_of_bytes);

	array_data.erase(std::remove(array_data.begin(), array_data.end(), ' '), array_data.end());
	if ((array_data.size() % 2) || !array_data.size())
	{
		return data;
	}

	data.reserve(array_data.size() / 2);

	std::mt19937 mt(static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count()));
	std::uniform_int_distribution<int32_t> dist(0, 15);
	char hexadecimal_character[] = "0123456789ABCDEF";

	for (size_t n = 0; n < array_data.size(); ++n)
	{
		if (!isxdigit(array_data.at(n)))
		{
			array_data.at(n) = hexadecimal_character[dist(mt)];
		}
	}

	for (size_t i = 0; i < array_data.size(); i += 2)
	{
		std::stringstream ss;
		ss << std::hex << array_data.at(i) << array_data.at(i + 1);
		data.push_back(static_cast<uint8_t>(std::stoi(ss.str(), nullptr, 16)));
	}

	return data;
}


std::vector<std::string> assembler::get_instructions() const
{
	return this->instructions;
}

bool assembler::insert_instruction(const std::string & instruction)
{
	this->instructions.push_back(instruction);
	return true;
}

bool assembler::bytecodes(uint64_t address, const std::string & instruction, std::vector<uint8_t>& instruction_bytecode)
{
	uint8_t *bytes = nullptr;
	size_t size = 0;
	size_t statement_size = 0;

	if (ks_asm(this->handle, instruction.c_str(), address, &bytes, &size, &statement_size) == 0)
	{
		std::copy(bytes, bytes + size, std::back_inserter(instruction_bytecode));
		return size > 0;
	}

	return false;	
}

std::vector<uint8_t> assembler::bytecodes(uint64_t address)
{
	std::string instruction;
	for (const std::string & ss : this->instructions)
	{
		instruction += ss + "\n";
	}

	std::vector<uint8_t> bytecode;
	this->bytecodes(address, instruction, bytecode);
	return bytecode;
}