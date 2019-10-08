#pragma once

#ifdef KEYSTONE_ASSEMBLER
#include "keystone\keystone.h"
#include <cstdint>
#include <vector>
#include <string>

class assembler
{
public:
	enum assembler_mode : int32_t
	{
		x86 = 1,
		x64
	};

	enum assembler_syntax : int32_t
	{
		intel = 1,
		att
	};

	explicit assembler(
		_In_ const std::vector<std::string> &instructions = std::vector<std::string>(),
		_In_ assembler_mode mode = x86, 
		_In_ assembler_syntax syntax = intel);

	~assembler() noexcept;

	std::vector<std::string> get_instructions() const;

	bool insert_instruction(_In_ const std::string &instruction);

	bool bytecodes(
		_In_ uint64_t address,
		_In_ const std::string &instruction, 
		_Inout_ std::vector<uint8_t> &instruction_bytecode);


	std::vector<uint8_t> bytecodes(uint64_t address);

private:
	ks_engine *handle;
	assembler::assembler_mode mode;
	assembler::assembler_syntax syntax;
	std::vector<std::string> instructions;
};

#endif