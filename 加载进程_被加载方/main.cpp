#include <windows.h>
#include <stdio.h>
#include <locale.h>

int main()
{
	setlocale(LC_ALL, "CHS");
	printf("���Ǳ����ط�����\n");
	MessageBox(NULL, TEXT("���Ǳ����ط�����"), TEXT("���Ǳ����ط�����"), MB_OK);
	getchar();
	return 0;
}