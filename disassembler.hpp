#pragma once
#include "capstone\capstone.h"
#include <cstdint>
#include <vector>
#include <string>

typedef csh disassembler_handle;
typedef cs_insn instruction;

struct assembly_instruction
{
	uint32_t mnemonic;
	std::vector<cs_x86_op> operand;

	x86_reg register_operand(cs_x86_op operand) const;
	int64_t immediate_operand(cs_x86_op operand) const;
	double floating_point_operand(cs_x86_op operand) const;
	x86_op_mem mem_operand(cs_x86_op operand) const;

	x86_reg register_operand(size_t operand_index) const;
	int64_t immediate_operand(size_t operand_index) const;
	double floating_point_operand(size_t operand_index) const;
	x86_op_mem mem_operand(size_t operand_index) const;
};


class disassembler
{
public:
	enum disassembler_mode : int32_t
	{
		x86 = 1,
		x64
	};

	disassembler(uint64_t address, const std::vector<uint8_t> &bytecode, disassembler_mode mode = x86);
	disassembler(uint64_t address, const std::string &filename, disassembler_mode mode = x86);
	~disassembler() noexcept;
	
	static const std::vector<uint8_t> readmemory(uint64_t address, size_t size);
	static const std::string byte_to_string(const std::vector<uint8_t>& bytes, const std::string &separator = " ");
	static const std::vector<uint8_t> string_to_bytes(const std::string & array_of_bytes);

	disassembler_handle get_handle() const;
	size_t size() const;

	std::vector<instruction> get_instructions() const;
	std::string get_instructions_string(const std::string &separator = "\n", const std::string &begin = "", const std::string &end = "");
	static std::string get_instructions_string(const std::vector<instruction> &instructions, const std::string &separator = "\n", const std::string &begin = "", const std::string &end = "");
	
	std::vector<uint8_t> get_bytecode() const;

	std::string get_register_name(x86_reg x86_register) const;

	assembly_instruction analyze_instruction(const instruction &n) const;

private:
	disassembler_handle handle;
	instruction *instructions;
	size_t instruction_size;

	std::vector<uint8_t> bytecode;
	disassembler_mode mode;
};
