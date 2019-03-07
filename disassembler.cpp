#include "disassembler.hpp"
#include "zephyrus.hpp"
#include <fstream>
#include <iterator>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <iomanip>

#pragma comment (lib, "capstone.lib")

disassembler::disassembler(uint64_t address, const std::vector<uint8_t>& bytecode, disassembler_mode mode)
	: bytecode(bytecode), mode(mode)
{
	cs_mode m = CS_MODE_32;

	switch (mode)
	{
	case x86:
		m = CS_MODE_32;
		break;

	case x64:
		m = CS_MODE_64;
		break;
	}

	cs_open(CS_ARCH_X86, m, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

	this->instruction_size = cs_disasm(handle, bytecode.data(), bytecode.size(), address, 0, &instructions);
}

disassembler::disassembler(uint64_t address, const std::string & filename, disassembler_mode mode)
{
	std::ifstream file(filename, std::ios::binary);
	file.unsetf(std::ios::skipws);

	file.seekg(0, std::ios::end);
	std::streampos filesize = file.tellg();
	file.seekg(0, std::ios::beg);
	
	std::vector<uint8_t> binary;
	binary.reserve(static_cast<size_t>(filesize));

	binary.insert(binary.begin(), std::istream_iterator<uint8_t>(file), std::istream_iterator<uint8_t>());

	disassembler::disassembler(address, binary, mode);
}

disassembler::~disassembler() noexcept
{
	cs_free(instructions, instruction_size);
	cs_close(&handle);
}

const std::string disassembler::byte_to_string(const std::vector<uint8_t>& bytes, const std::string &separator)
{
	return zephyrus::byte_to_string(bytes, separator);
}

const std::vector<uint8_t> disassembler::string_to_bytes(const std::string & array_of_bytes)
{
	return zephyrus::string_to_bytes(array_of_bytes);
}

disassembler_handle disassembler::get_handle() const
{
	return this->handle;
}

size_t disassembler::size() const
{
	return this->instruction_size;
}

std::vector<instruction> disassembler::get_instructions() const
{
	std::vector<instruction> instructions;
	instructions.reserve(this->size());

	for (size_t n = 0; n < this->size(); ++n)
	{
		instructions.push_back(this->instructions[n]);
	}

	return instructions;
}

std::string disassembler::get_instructions_string(const std::string & separator, const std::string &begin, const std::string &end)
{
	std::stringstream stream;

	for (size_t n = 0; n < this->size(); ++n)
	{
		stream << begin << this->instructions[n].mnemonic << ' ' << this->instructions[n].op_str << end;
		
		if (n + 1 != this->size())
		{
			stream << separator;
		}
	}
	
	std::string result(stream.str());

	std::transform(result.begin(), result.end(), result.begin(), toupper);

	return result;
}

std::vector<uint8_t> disassembler::get_bytecode() const
{
	return this->bytecode;
}

std::string disassembler::get_register_name(x86_reg x86_register) const
{
	return std::string(cs_reg_name(this->get_handle(), x86_register));
}

assembly_instruction disassembler::analyze_instruction(const instruction & n) const
{
	cs_x86 x86 = n.detail->x86;

	assembly_instruction detail;
	detail.mnemonic = n.id;
	detail.operand.reserve(x86.op_count);

	for (uint8_t m = 0; m < x86.op_count; ++m)
	{
		detail.operand.push_back(x86.operands[m]);
	}

	return detail;
}

x86_reg assembly_instruction::register_operand(cs_x86_op operand) const
{
	return operand.reg;
}

int64_t assembly_instruction::immediate_operand(cs_x86_op operand) const
{
	return operand.imm;
}

double assembly_instruction::floating_point_operand(cs_x86_op operand) const
{
	return operand.fp;
}

x86_op_mem assembly_instruction::mem_operand(cs_x86_op operand) const
{
	return operand.mem;
}

x86_reg assembly_instruction::register_operand(size_t operand_index) const
{
	return this->register_operand(this->operand.at(operand_index));
}

int64_t assembly_instruction::immediate_operand(size_t operand_index) const
{
	return this->immediate_operand(this->operand.at(operand_index));
}

double assembly_instruction::floating_point_operand(size_t operand_index) const
{
	return this->floating_point_operand(this->operand.at(operand_index));
}

x86_op_mem assembly_instruction::mem_operand(size_t operand_index) const
{
	return this->mem_operand(this->operand.at(operand_index));
}
