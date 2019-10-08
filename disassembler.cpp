#include "disassembler.hpp"
#include <windows.h>
#include <fstream>
#include <functional>
#include <iterator>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <iomanip>

#ifdef X86
#pragma comment (lib, "capstone.lib")
#pragma comment (lib, "detours.lib")
#elif X64
#pragma comment (lib, "capstone64.lib")
#pragma comment (lib, "detours64.lib")
#else
#pragma comment (lib, "capstone.lib")
#pragma comment (lib, "detours.lib")
#endif

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

const std::vector<uint8_t> disassembler::readmemory(uint64_t address, size_t size)
{
	auto pageexecutereadwrite = [&](uint64_t address, size_t size, const std::function<void(void)>& function)
	{
		auto pagereadwriteaccess = [](uint64_t address)
		{
			MEMORY_BASIC_INFORMATION mbi = { 0 };

			if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
			{
				return false;
			}

			if (!mbi.Protect || (mbi.Protect & PAGE_GUARD))
			{
				return false;
			}

			if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
			{
				return false;
			}

			return true;
		};


		DWORD protect = 0;

		if (!pagereadwriteaccess(address))
		{
			protect = VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &protect) ? protect : 0;
		}

		function();

		if (protect)
		{
			return VirtualProtect(reinterpret_cast<void*>(address), size, protect, &protect) != FALSE;
		}

		return true;
	};

	std::vector<uint8_t> memory;
	memory.reserve(size);

	pageexecutereadwrite(address, size, [&]()
	{
		for (size_t i = 0; i < size; i++)
		{
			memory.push_back(*reinterpret_cast<uint8_t*>(address + i));
		}
	});

	return memory;
}

const std::string disassembler::byte_to_string(const std::vector<uint8_t>& bytes, const std::string &separator)
{
	std::stringstream stream;
	for (size_t n = 0; n < bytes.size(); ++n)
	{
		if (!separator.compare("\\x"))
		{
			stream << separator << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int32_t>(bytes.at(n));
		}
		else
		{
			stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int32_t>(bytes.at(n));

			if (bytes.size() - 1 != n)
			{
				stream << separator;
			}
		}
	}

	return stream.str();
}

const std::vector<uint8_t> disassembler::string_to_bytes(const std::string & array_of_bytes)
{
	std::string aob(array_of_bytes);
	std::vector<uint8_t> bytes;

	aob.erase(std::remove(aob.begin(), aob.end(), ' '), aob.end());
	if (aob.empty() || aob.size() % 2)
	{
		return bytes;
	}

	bytes.reserve(aob.size() / 2);

	std::mt19937 mt(static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count()));
	std::uniform_int_distribution<int16_t> dist(0, 15);
	std::stringstream stream;

	for (auto it = aob.begin(); it != aob.end(); ++it)
	{
		if (!isxdigit(*it))
		{
			stream << std::hex << std::setw(1) << dist(mt);
		}
		else
		{
			stream << std::hex << std::setw(1) << *it;
		}

		if (stream.str().size() == 2)
		{
			bytes.push_back(std::stoi(stream.str(), 0, 16));
			stream.str("");
		}
	}

	return bytes;
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

std::string disassembler::get_instructions_string(const std::vector<instruction> &instructions, const std::string & separator, const std::string &begin, const std::string &end)
{
	std::stringstream stream;

	for (size_t n = 0; n < instructions.size(); ++n)
	{
		stream << begin << instructions.at(n).mnemonic << ' ' << instructions.at(n).op_str << end;

		if (n + 1 != instructions.size())
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
