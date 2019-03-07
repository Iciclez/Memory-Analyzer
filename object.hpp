#pragma once
#include <windows.h>
#include <dbghelp.h>
#include <cstdint>
#include <sstream>
#include <vector>
#include <unordered_map>

class object
{
public:
	enum edit_type : int32_t
	{
		modification,
		remodification,
		reverted
	};

	object(HMODULE module_handle);
	object(IMAGE_NT_HEADERS *nt);
	~object();

	uint32_t memory_start() const;
	uint32_t memory_end() const;
	size_t memory_size() const;

	void initialize();

	void api_hook_check();
	void memory_patch_check();

	void on_memory_patch(edit_type type, uint32_t address, size_t size, const std::vector<uint8_t> &from, const std::vector<uint8_t> &to);
	void on_api_hook(void *from, void *to, const std::string &module_from, const std::string &module_to);

private:
	IMAGE_NT_HEADERS *nt;

	HMODULE module_handle;

	std::vector<uint8_t> memory_instance;
	std::unordered_map<uint32_t, std::vector<uint8_t>> memory_edit;

	std::unordered_map<void*, void*> api_hook;
	std::unordered_map<void*, std::string> api_name;
};

class object_hash
{
public:
	std::size_t operator()(const object & memory_object) const;
};

class object_compare
{
public:
	std::size_t operator()(const object & memory_object_1, const object & memory_object_2) const;
};