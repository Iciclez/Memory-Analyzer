#pragma once
#include <vector>
#include <unordered_map>
#include <cstdint>

class memory_analyzer
{
public:
	memory_analyzer();
	~memory_analyzer();

	void begin_analysis_work();
	bool api_hook_check();

	std::vector<uint8_t> get_memory_instance() const;

	void *get_module_begin();
	void *get_module_end();

	static const std::string byte_to_string(const std::vector<uint8_t>& bytes, const std::string & separator = " ");

private:
	std::vector<uint8_t> memory_instance;
	std::unordered_map<uint32_t, std::vector<uint8_t>> memory_edit;

	void *module_begin;
	void *module_end;

};

