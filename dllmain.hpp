#pragma once
#include <windows.h>
#include "logger.hpp"
#include "zephyrus.hpp"

class dllmain
{
public:
	dllmain();
	~dllmain() noexcept;

	static void on_attach(HINSTANCE instance);
	static void on_detach();
};

extern logger l;
extern zephyrus z;