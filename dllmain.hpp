#pragma once

class dllmain
{
public:
	dllmain();
	~dllmain() noexcept;

	static void on_attach();
	static void on_detach();
};