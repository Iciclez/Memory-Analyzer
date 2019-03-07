#include "zephyrus.hpp"
#include "assembler.hpp"
#include "disassembler.hpp"

#include <windows.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <algorithm>

#include "detours.h"

#pragma comment (lib, "detours.lib")

zephyrus z;

zephyrus::zephyrus(padding_byte padding)
	: padding(padding)
{
	this->pageexecutereadwrite = [&](address_t address, size_t size, const std::function<void(void)> &function)
	{
		DWORD protect = 0;

		if (!this->pagereadwriteaccess(address))
		{
			protect = this->protectvirtualmemory(address, size);
		}

		function();

		if (protect)
		{
			return VirtualProtect(reinterpret_cast<void*>(address), size, protect, &protect) != FALSE;
		}

		return true;
	};

	HANDLE process = GetCurrentProcess();
	HANDLE token = 0;
	if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES, &token))
	{
		CloseHandle(token);
		CloseHandle(process);
		return;
	}

	LUID luid = { 0 };
	if (!LookupPrivilegeValueA(0, "SeDebugPrivilege", &luid))
	{
		CloseHandle(token);
		CloseHandle(process);
		return;
	}

	TOKEN_PRIVILEGES privileges = { 0 };
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(token, false, &privileges, 0, 0, 0);

	CloseHandle(token);
	CloseHandle(process);
}

zephyrus::~zephyrus() noexcept
{
}

bool zephyrus::pagereadwriteaccess(address_t address)
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
}

uint32_t zephyrus::protectvirtualmemory(address_t address, size_t size)
{
	DWORD protection = 0;
	return VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &protection) ? protection : 0;
}

const std::vector<uint8_t> zephyrus::readmemory(address_t address, size_t size)
{
	std::vector<uint8_t> memory;
	memory.reserve(size);

	this->pageexecutereadwrite(address, size, [&]()
	{
		for (size_t i = 0; i < size; i++)
		{
			memory.push_back(*reinterpret_cast<uint8_t*>(address + i));
		}
	});

	return memory;
}

bool zephyrus::writememory(address_t address, const std::string & array_of_bytes, size_t padding_size, bool retain_bytes)
{
	std::vector<uint8_t> data = string_to_bytes(array_of_bytes);
	
	data.insert(data.end(), padding_size, static_cast<uint8_t>(padding));

	return this->writememory(address, data, retain_bytes);
}

bool zephyrus::writememory(address_t address, const std::vector<uint8_t>& bytes, bool retain_bytes)
{
	return this->pageexecutereadwrite(address, bytes.size(), [&]()
	{
		if (retain_bytes)
		{
			memoryedit[address] = this->readmemory(address, bytes.size());
		}

		for (size_t i = 0; i < bytes.size(); ++i)
		{
			*reinterpret_cast<uint8_t*>(address + i) = bytes.at(i);
		}

	});
}

bool zephyrus::copymemory(address_t address, void *bytes, size_t size, bool retain_bytes)
{
	return this->pageexecutereadwrite(address, size, [&]()
	{
		if (retain_bytes)
		{
			memoryedit[address] = this->readmemory(address, size);
		}


		memcpy(reinterpret_cast<void*>(address), bytes, size);
	});
}

bool zephyrus::writeassembler(address_t address, const std::string & assembler_code, bool retain_bytes)
{
	std::vector<uint8_t> bytecodes;

	if (!this->assemble(assembler_code, bytecodes))
	{
		return false;
	}

	return this->writememory(address, bytecodes, retain_bytes);
}

bool zephyrus::writepadding(address_t address, size_t padding_size)
{
	std::vector<uint8_t> padding_bytes;

	padding_bytes.resize(padding_size, static_cast<uint8_t>(padding));

	return this->writememory(address, padding_bytes, false);
}

bool zephyrus::revertmemory(address_t address)
{
	try
	{
		return this->writememory(address, memoryedit.at(address), false);
	}
	catch (std::exception &)
	{
		return false;
	}
}

bool zephyrus::redirect(hook_operation operation, address_t * address, address_t function, bool enable)
{
	if (enable)
	{
#ifdef X64
		size_t size = operation == JMP ? 14 : static_cast<size_t>(-1) + this->getnopcount(*address, operation);
#else
		size_t size = 5 + (operation > 0xff ? 1 : 0) + this->getnopcount(*address, operation);
#endif

#ifdef X64
		const size_t JMP_SIZE = 14;
#else
		const size_t JMP_SIZE = 5;
#endif

		//insert trampoline
		std::vector<uint8_t> trampoline = this->readmemory(*address, size);
#ifdef X64

		//additional step in x64 where we will have to take our trampoline bytes ->
		//dump it into disassembler & reassemble the opcodes to ensure accuracy of bytes
		
		std::vector<instruction> instructions = disassembler(reinterpret_cast<address_t>(trampoline.data()), trampoline, disassembler::x64).get_instructions();
		std::string assembler_instruction = "";
		for (const instruction & i : instructions)
		{
			//assembler_instruction += i.mnemonic;
			//assembler_instruction += " ";
			//assembler_instruction += i.op_str;
			//assembler_instruction += "\n";
			printf("%p: %s %s\n", i.address, i.mnemonic, i.op_str);
		}

		//this->assemble(assembler_instruction, trampoline);
		
#endif
		trampoline.resize(trampoline.size() + JMP_SIZE);
		this->trampoline_table[*address] = trampoline;
		this->sethook(JMP, reinterpret_cast<address_t>(this->trampoline_table[*address].data() + this->trampoline_table[*address].size() - JMP_SIZE), *address + size, 0, false);

		//enable page_readwrite_execute in trampoline
		this->protectvirtualmemory(reinterpret_cast<address_t>(this->trampoline_table[*address].data()), this->trampoline_table[*address].size());

		//relocate address ptr to trampoline function
		this->trampoline_detour[reinterpret_cast<address_t>(this->trampoline_table[*address].data())] = *address;
		*address = reinterpret_cast<address_t>(this->trampoline_table[*address].data());

		return this->sethook(operation, this->trampoline_detour[*address], function);
	}

	//restores address from our trampoline detour
	*address = this->trampoline_detour[*address];

	//remove trampoline_detour and trampoline_table

	for (std::unordered_map<address_t, address_t>::iterator it = this->trampoline_detour.begin(); it != this->trampoline_detour.end(); ++it)
	{
		//std::pair<> of relocated_address to our real_address
		if ((*it).second == *address)
		{
			this->trampoline_detour.erase(it);
		}
	}

	for (std::unordered_map<address_t, std::vector<uint8_t>>::iterator it = this->trampoline_table.begin(); it != this->trampoline_table.end(); ++it)
	{
		//std::pair<> of real_address to trampoline bytes
		if ((*it).first == *address)
		{
			this->trampoline_table.erase(it);
		}
	}

	return this->revertmemory(*address);
}

bool zephyrus::redirect(address_t * address, address_t function, bool enable)
{
	return this->redirect(JMP, address, function, enable);
}

bool zephyrus::detour(void ** from, void *to, bool enable)
{
	if (DetourTransactionBegin() != NO_ERROR)
	{
		return false;
	}

	if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
	{
		DetourTransactionAbort();
		return false;
	}

	if ((enable ? DetourAttach : DetourDetach)(from, to) != NO_ERROR)
	{
		DetourTransactionAbort();
		return false;
	}

	return DetourTransactionCommit() == NO_ERROR;
}

bool zephyrus::sethook(hook_operation operation, address_t address, address_t function, size_t nop_count, bool retain_bytes)
{
	//TODO X64
	if (nop_count == -1)
	{
		nop_count = this->getnopcount(address, operation);
	}

#ifdef X64

	size_t size = operation == JMP ? 14 : static_cast<size_t>(-1);

	return this->pageexecutereadwrite(address, size, [&]()
	{
		if (retain_bytes)
		{
			memoryedit[address] = this->readmemory(address, size);
		}

		std::vector<uint8_t> bytes;

		if (operation == JMP)
		{
			std::vector<uint8_t> x64jmp = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
			bytes.insert(bytes.end(), x64jmp.begin(), x64jmp.end());
	}
		/*
		else if (operation == CALL)
		{
		std::vector<uint8_t> x64call = { 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xE8, 0x08 };
		bytes.insert(bytes.end(), x64call.begin(), x64call.end());
		}
		*/
		else
		{
			throw std::exception("exception operation not supported");
		}

		std::vector<uint8_t> pfunction = this->readmemory(reinterpret_cast<address_t>(&function), 8);
		bytes.insert(bytes.end(), pfunction.begin(), pfunction.end());

		bytes.insert(bytes.end(), nop_count, static_cast<uint8_t>(padding));

		this->writememory(address, bytes, false);
	});

#else
	int32_t i = operation > 0xff ? 1 : 0;
	size_t size = 5 + i + nop_count;

	return this->pageexecutereadwrite(address, size, [&]()
	{
		if (retain_bytes)
		{
			memoryedit[address] = this->readmemory(address, size);
		}

		*reinterpret_cast<address_t*>(address) = operation;
		*reinterpret_cast<address_t*>(address + 1 + i) = static_cast<address_t>(function - address - 5 - i);
		this->writepadding(address + 5 + i, nop_count);
	});
#endif
}

bool zephyrus::sethook(hook_operation operation, address_t address, const std::string & assembler_code, size_t nop_count, bool retain_bytes)
{
	std::vector<uint8_t> bytecodes;
	
	if (!this->assemble(assembler_code, bytecodes))
	{
		return false;
	}

	this->hook_memory[address] = bytecodes;

	return this->sethook(operation, address, reinterpret_cast<address_t>(this->hook_memory[address].data()), nop_count, retain_bytes);
}

bool zephyrus::sethook(hook_operation operation, address_t address, const std::vector<std::string>& assembler_code, size_t nop_count, bool retain_bytes)
{
	std::string assembler = "";

	for (const std::string & instruction : assembler_code)
	{
		assembler += instruction + "\n";
	}
	
	return this->sethook(operation, address, assembler, nop_count, retain_bytes);
}

bool zephyrus::assemble(const std::string & assembler_code, std::vector<uint8_t>& bytecode)
{
	return assembler(std::vector<std::string>(), 
#ifdef X64
		assembler::x64
#else
		assembler::x86
#endif
	).bytecodes(reinterpret_cast<uint64_t>(bytecode.data()), assembler_code, bytecode);
}

size_t zephyrus::getnopcount(address_t address, hook_operation operation)
{
#ifdef X64

	size_t hooksize = operation == JMP ? 14 : static_cast<size_t>(-1);
	std::vector<instruction> instructions = disassembler(static_cast<uint64_t>(address), this->readmemory(address, 32), disassembler::x64).get_instructions();


#else
	size_t hooksize = 5 + (operation > 0xff ? 1 : 0);
	std::vector<instruction> instructions = disassembler(static_cast<uint64_t>(address), this->readmemory(address, 12)).get_instructions();

#endif

	for (size_t n = 0, m = 0; n < instructions.size(); ++n)
	{
		if (instructions.at(n).size + m < hooksize)
		{
			m += instructions.at(n).size;
		}
		else
		{
			return instructions.at(n).size + m - hooksize;
		}
	}

	return static_cast<size_t>(-1);
}

const std::string zephyrus::byte_to_string(const std::vector<uint8_t>& bytes, const std::string & separator)
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

const std::vector<uint8_t> zephyrus::string_to_bytes(const std::string & array_of_bytes)
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

address_t zephyrus::getexportedfunctionaddress(const std::string & module_name, const std::string & function_name)
{
	HMODULE module = GetModuleHandleA(module_name.c_str());
	if (!module)
	{
		module = LoadLibraryA(module_name.c_str());
		if (!module)
		{
			return 0;
		}
	}

	return reinterpret_cast<address_t>(GetProcAddress(module, function_name.c_str()));
}
