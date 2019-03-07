#include "assembler.hpp"
#include "zephyrus.hpp"
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <iomanip>

#pragma comment (lib, "keystone.lib")

assembler::assembler(const std::vector<std::string>& instructions, assembler_mode mode, assembler_syntax syntax)
	: instructions(instructions), mode(mode), syntax(syntax)
{
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
	return zephyrus::byte_to_string(bytes, separator);
}

const std::vector<uint8_t> assembler::string_to_bytes(const std::string & array_of_bytes)
{
	return zephyrus::string_to_bytes(array_of_bytes);
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
	std::stringstream instruction;
	for (const std::string & ins : this->instructions)
	{
		instruction << ins << '\n';
	}

	std::vector<uint8_t> bytecode;
	this->bytecodes(address, instruction.str(), bytecode);
	return bytecode;
}