make:
	x86_64-w64-mingw32-gcc RtlpAddVectoredExceptionHandler.c -o RtlpAddVectoredExceptionHandler.exe -O2 -lntdll