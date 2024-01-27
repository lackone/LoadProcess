#include <windows.h>
#include <stdio.h>
#include <locale.h>

int main()
{
	setlocale(LC_ALL, "CHS");
	printf("我是被加载方进程\n");
	MessageBox(NULL, TEXT("我是被加载方进程"), TEXT("我是被加载方进程"), MB_OK);
	getchar();
	return 0;
}