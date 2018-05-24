#include "memory_analyzer.hpp"
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>

#include <thread>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include "detours.h"
#include "zephyrus.hpp"
#include "disassembler.hpp"

memory_analyzer::memory_analyzer()
{
	PIMAGE_NT_HEADERS nt = ImageNtHeader(GetModuleHandle(0));

	this->module_begin = reinterpret_cast<void*>(nt->OptionalHeader.ImageBase + nt->OptionalHeader.BaseOfCode);
	this->module_end = reinterpret_cast<uint8_t*>(this->module_begin) + nt->OptionalHeader.SizeOfCode;

	memory_instance.insert(memory_instance.end(), 
		reinterpret_cast<uint8_t*>(this->module_begin), 
		reinterpret_cast<uint8_t*>(this->module_end));

	DWORD previous_protection = 0;
	VirtualProtect(this->module_begin, nt->OptionalHeader.SizeOfCode, PAGE_EXECUTE_READWRITE, &previous_protection);

	std::cout << "Initializing Memory Analyzer from " <<  
		std::hex << std::setw(8) << std::setfill('0') << this->module_begin <<
		" to " <<
		std::hex << std::setw(8) << std::setfill('0') << this->module_end << std::endl;

}


memory_analyzer::~memory_analyzer()
{
}

void memory_analyzer::begin_analysis_work()
{
	uint32_t instance_module_begin = reinterpret_cast<uint32_t>(this->get_module_begin());
	while (true)
	{
		this->api_hook_check();
		for (size_t n = 0; n < memory_instance.size(); ++n)
		{
			uint32_t current_memory_address = instance_module_begin + n;
			if (memory_edit.count(current_memory_address) > 0)
			{
				std::vector<uint8_t> modified = memory_edit.at(current_memory_address);
				std::vector<uint8_t> current;
				std::vector<uint8_t> original;

				for (size_t x = 0; x < modified.size(); ++x)
				{
					current.push_back(*reinterpret_cast<uint8_t*>(instance_module_begin + n + x));
					original.push_back(memory_instance.at(n + x));
				}

				

				//std::cout << byte_to_string(modified) << std::endl;
				//std::cout << byte_to_string(current) << std::endl;
				//std::cout << byte_to_string(original) << std::endl;

				//current memory is no longer the same as the saved instance of altered memory
				if (modified.size() != current.size() || !std::equal(current.begin(), current.end(), modified.begin()))
				{					
					//reverted back to original
					if (std::equal(current.begin(), current.end(), original.begin()))
					{
						std::cout << "Reverted - " <<
							std::hex << std::setw(8) << std::setfill('0') << (instance_module_begin + n) <<
							":(" << std::dec << modified.size() << ") " <<
							byte_to_string(modified) << " to " << byte_to_string(current) << std::endl;

						memory_edit.erase(instance_module_begin + n);
					}
					//changed to other memory
					else
					{
						std::cout << "Re-Modification - " <<
							std::hex << std::setw(8) << std::setfill('0') << (instance_module_begin + n) <<
							":(" << std::dec << modified.size() << ") " <<
							byte_to_string(modified) << " to " << byte_to_string(current) << std::endl;

						memory_edit.at(instance_module_begin + n) = current;

					}
				}
				n += modified.size() - 1;
			}
			else
			{
				if (memory_instance.at(n) != *reinterpret_cast<uint8_t*>(current_memory_address))
				{
					std::vector<uint8_t> original;
					std::vector<uint8_t> modified;
					size_t m = n;
					while (memory_instance.at(m) != *reinterpret_cast<uint8_t*>(instance_module_begin + m))
					{
						original.push_back(memory_instance.at(m));
						modified.push_back(*reinterpret_cast<uint8_t*>(instance_module_begin + m));
						++m;
					}

					std::cout << "Modification - " <<
						std::hex << std::setw(8) << std::setfill('0') << current_memory_address <<
						":(" << std::dec << (m - n) << ") " <<
						byte_to_string(original) << " to " << byte_to_string(modified) << std::endl;

					memory_edit.emplace(current_memory_address, modified);

					n = m;
				}
			}
		}
	}
}

bool memory_analyzer::api_hook_check()
{
	HMODULE module[1024] = { 0 };
	DWORD aggregate_size = 0;
	BOOL result = TRUE;

	if (!EnumProcessModules(GetCurrentProcess(), module, sizeof(module), &aggregate_size))
	{
		return false;
	}

	size_t size = aggregate_size / sizeof(HMODULE);
	for (size_t n = 0; n < size; ++n)
	{
		result &= DetourEnumerateExports(module[n], module[n], [](PVOID pContext, ULONG nOrdinal, LPCSTR pszName, PVOID pCode) -> BOOL
		{
			static std::unordered_map<void*, void*> api_hook;

			if (*reinterpret_cast<uint8_t*>(pCode) == hook_operation::JMP)
			{
				disassembler memory(reinterpret_cast<address_t>(pCode), z.readmemory(reinterpret_cast<address_t>(pCode), 5));
				void *address_to = reinterpret_cast<void*>(memory.analyze_instruction(memory.get_instructions().at(0)).operand.at(0).imm);

				if (api_hook.count(pCode) == 0 || api_hook.at(pCode) != address_to)
				{
					char module_name_from[512];
					char module_name_to[512];

					GetMappedFileNameA(GetCurrentProcess(), pCode, module_name_from, sizeof(module_name_from));
					GetMappedFileNameA(GetCurrentProcess(), address_to, module_name_to, sizeof(module_name_to));

					std::cout << "API Hook - " << module_name_from << ":" << pszName << "(" << pCode << ") -> " <<
						(strrchr(module_name_to, '\\') + 1) << ":" << address_to << std::endl;

					api_hook.emplace(pCode, address_to);
				}
				
			}

			return TRUE;
		});
	}

	return result != FALSE;
}

std::vector<uint8_t> memory_analyzer::get_memory_instance() const
{
	return this->memory_instance;
}

void * memory_analyzer::get_module_begin()
{
	return this->module_begin;
}

void * memory_analyzer::get_module_end()
{
	return this->module_end;
}


const std::string memory_analyzer::byte_to_string(const std::vector<uint8_t>& bytes, const std::string & separator)
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