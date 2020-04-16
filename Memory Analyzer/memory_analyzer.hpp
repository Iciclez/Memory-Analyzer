#pragma once
#include <windows.h>
#include <vector>
#include <unordered_set>

#include "object.hpp"

class memory_analyzer
{
public:
	memory_analyzer();
	~memory_analyzer();

	void begin_analysis_work();

	static std::pair<bool, std::vector<HMODULE>> get_process_modules();

private:	
	std::unordered_set<object, object_hash, object_compare> memory_object_set;
	std::vector<object> memory_objects;
};

