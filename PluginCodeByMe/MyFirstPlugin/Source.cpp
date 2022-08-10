#include <Windows.h>
#include "plugin.h"
#include <iostream>
#include <fstream>
using namespace std;

////////////////////////////////////////////////
//plugin.h中有如下定義：////                                                                      
//////////////////////////////////////////////
/*
#ifdef __cplusplus
#define extc           extern "C"    // Assure that names are not mangled
#else
#define extc           extern
#endif

#define _export        __declspec(dllexport)
*/


/************************************************************************
函數名稱：_ODBG_Plugindata
函數功能：設置插件的名字
參    數：shortname  插件名字
返 回 值：ollydbg版本號
備    注：必須存在的函數之一
************************************************************************/
extc int _export cdecl  ODBG_Plugindata(char* shortname) {
	const char* pluginName = "我的插件例子";
	strcpy_s(shortname, strlen(pluginName) + 1, pluginName);
	return PLUGIN_VERSION;
}
/************************************************************************
函數名稱：_ODBG_Plugininit
函數功能：初始化插件
參  數 1：ollydbgversion 當前OD的版本
參  數 2：hw ollydbg主窗口的句柄
參  數 3：features 拓展，暫時無用
返 回 值：正常返回null,異常返回-1
備    注：必須存在的函數之一
************************************************************************/
HWND gODHwnd;
extc int _export cdecl _ODBG_Plugininit(int ollydbgversion, HWND hw, ulong* features){
	gODHwnd = hw;
	//檢查插件版本與調試器版本是否兼容
	if (ollydbgversion < PLUGIN_VERSION)
	{
		return -1;
	}
	return 0;
}

/************************************************************************
函數名稱：_ODBG_Pluginmenu
函數功能：添加菜單
參  數 1：origin 用戶點擊的菜單下標
參  數 2：data   子菜單名稱緩衝區
參  數 3：item   根據origin的不同，item會傳入不同的結構體
返 回 值：正常返回TRUE,異常返回FALSE
備    注：每個菜單項之間用'|'or','字符隔開
************************************************************************/
extc int  _export cdecl _ODBG_Pluginmenu(int origin, char data[4096], void* item){
	//PM_DISASM代表在OD的反匯編窗口
	if (origin == PM_DISASM) {
		strcpy_s(data, 4096, "我的插件{0&call重命名}"); //子菜單寫法，數字是每個item的編號( 只要不一樣就可以，不一定要按順序，但數值不能太大 )
	}
	//PM_DISASM代表數據窗口
	if (origin == PM_CPUDUMP) {
		strcpy_s(data, 4096, "我的插件{0&Memory Dump to exe}");
	}
	//PM_MAIN代表主窗口
	if (origin == PM_MAIN) {
		strcpy_s(data, 4096, "0&JCC追蹤記錄");
	}

	return TRUE;
}

bool StrIsBeginWith(const char* preStr, const char* targetStr) {
	size_t preLen = strlen(preStr);
	size_t targetLen = strlen(targetStr);
	return targetLen < preLen ? false : strncmp(preStr, targetStr, preLen) == 0;
}

/************************************************************************
函數名稱：RenameCall
函數功能：函數重命名
參  數 1：當前反匯編窗口選中的塊的描述信息
返 回 值：無
************************************************************************/
void RenameCall(t_dump* ptDump) {
	//反匯編窗口選中的範圍為：[ptDump->sel0,ptDump->sel1)
	ulong uSelectAddress = ptDump->sel0;
	if (uSelectAddress == 0) {  //代表沒選中任何東西
		return;
	}
	//MAXCMDSIZE = 16，因為硬編碼最長不超過16(<=15)
	uchar pBuffer[MAXCMDSIZE];
	Readmemory(pBuffer, uSelectAddress, MAXCMDSIZE, MM_SILENT);
	//call有兩種，一種是0xE8，一種是0xFF 0x15，這插件只針對前者
	if (pBuffer[0] != 0xE8) {
		return;
	}
	//定義一個反匯編引擎
	t_disasm td;
	ulong lSize = Disasm(pBuffer, 16, uSelectAddress, NULL, &td, DISASM_ALL, NULL);
	if (!StrIsBeginWith("call", td.result)) {
		return;
	}
	uchar bufOffset[4];
	//讀取call XXXXXXXX 中的XXXXXXXX
	Readmemory(bufOffset, uSelectAddress + 1, 4, MM_SILENT);
	int nOffset;
	//轉整數
	memcpy_s(&nOffset, 4, bufOffset, 4);
	//計算call的目標地址(公式：目標地址 - 源地址 - 5 = XXXXXXXX )
	int callTargetAddress = uSelectAddress + nOffset + 5;

	char szUserInput[TEXTLEN] = { 0 };
	//獲取callTargetAddress原來的標籤
	Findlabel(callTargetAddress, szUserInput);
	//跳出對話框，讓用戶輸入
	if (Gettext((char*)"請輸入數據", szUserInput, 0, NM_NONAME, 0) != -1) {
		//插入標籤( NM_LABEL )，若改成NM_COMMENT則插入注釋
		Insertname(callTargetAddress, NM_LABEL, szUserInput);
	}
}


/************************************************************************
函數名稱：MemDump
函數功能：將內存的數據Dump下來
參  數 1：當前反匯編窗口選中的塊的描述信息
返 回 值：無
************************************************************************/
void MemDump(t_dump* ptDump) {
	ulong uSelectAddress = ptDump->sel0;
	if (uSelectAddress == 0) {  //代表沒選中任何東西
		return;
	}
	ulong dataSize;
	//輸入要dump的大小
	if (Getlong((char*)"請輸入數據大小", &dataSize, 4, 0, DIA_ASKGLOBAL) == -1) {
		return;
	}
	char* buf = new char[dataSize];
	//獲取[uSelectAddress,uSelectAddress+dataSize]範圍的內容
	Readmemory(buf, uSelectAddress, dataSize, MM_SILENT);
	//存放到OD根目錄下，名為dump.exe
	ofstream ofs("dump.exe", ios::binary | ios::out);
	ofs.write(buf, dataSize);
	MessageBox(gODHwnd, "dump成功，文件位於OD根目錄下", "提示", MB_OK);

	ofs.close();
	delete[] buf;
}


#include <vector>
struct Info
{
	ulong address;
	char* msg;
};
vector<Info> infoArr;
ulong nextAddress = 0;
bool flag = false;

/************************************************************************
函數名稱：JccRecord
函數功能：在OD日志窗口(alt+l)記錄跳轉指令的實現與否
返 回 值：無
************************************************************************/
void JccRecord() {
	//獲取CPU反匯編窗口的t_dump結構體
	t_dump* t_diasm = (t_dump*)Plugingetvalue(VAL_CPUDASM);
	/***以下操作是獲取當前地址的匯編指令(存放在td.result中)***/
	byte buf[16] = { 0 }; //長度16是因為硬編碼就長不超過16(<=15)
	ulong currentAddress = t_diasm->sel0;
	Readmemory(buf, currentAddress, 16, MM_SILENT);
	t_disasm td;
	ulong lSize = Disasm(buf, 16, currentAddress, NULL, &td, DISASM_ALL, NULL); //反匯編引擎
	//判斷nextAddress是否為0，不為0即代表上一條指令是JCC指令
	if (nextAddress != 0) {
		//若nextAddress == currentAddress即代表上一條跳轉指令沒有實現
		if (nextAddress == currentAddress)
			infoArr[0].msg = (char*)"跳轉未實現";
		else
			infoArr[0].msg = (char*)"跳轉已實現";
		//在日志窗口顯示出來
		Addtolist(infoArr[0].address, 1, (char*)infoArr[0].msg);
		//清空infoArr數組(讓其保持size=1)
		infoArr.clear();
		nextAddress = 0;
	}
	//簡單判斷匯編指令是否以'j'開頭，若是則為跳轉指令(雖然很有可能出錯，但不管)
	if (td.result[0] == 'j') {
		Info tmp;
		tmp.address = currentAddress;
		tmp.msg = (char*)"未知跳轉";
		nextAddress = t_diasm->sel1;
		infoArr.emplace_back(tmp);
	}

	//遇到int3斷點時就停下
	if (buf[0] == 0xCC) {
		//初始化
		flag = false;
		nextAddress = 0;
		infoArr.clear();
		return;
	}
	//若不是int3斷點則繼續F8
	Go(0, 0, STEP_OVER, 0, 0);
}

/************************************************************************
函數名稱：_ODBG_Pausedex
函數功能：可選回調函數，如果使用，OD在被調試程序暫停時或一個內部進程完成時調用本函數
參  數 1：reason 應用程序暫停原因
參  數 2：extdata 保留，總為0
參  數 3：reg 指向已暫停應用程序的線程寄存器，可為NULL
參  數 4：debugevent 指向暫停發生時的調試事件，可為NULL(如果無調試事件)
返 回 值：無
************************************************************************/
extc int _export cdecl _ODBG_Pausedex(int reason, int extdata, t_reg* reg, DEBUG_EVENT* debugevent) {
	//reason：單步步入(F7)和單步步過(F8)都是PP_SINGLESTEP
	//注：只有單步步過(F8)call指令時才是PP_HWBREAK	
	if (flag) {
		if (reason == PP_SINGLESTEP || reason == PP_HWBREAK) {
			JccRecord();
		}
	}
	return 1;
}




/************************************************************************
函數名稱：_ODBG_Pluginaction
函數功能：響應菜單事件
參  數 1：origin 用戶點擊的菜單下標
參  數 2：action 點擊的子菜單ID(在_ODBG_Pluginmenu函數中設置)
參  數 3：item 根據origin的不同，item會傳入不同的結構體
返 回 值：無
************************************************************************/
extc void _export cdecl _ODBG_Pluginaction(int origin, int action, void* item)
{
	//如果是在數據窗口中點擊
	if (origin == PM_CPUDUMP) {
		switch (action)
		{
		case 0:
			MemDump((t_dump*)item);
			break;
		}
	}
	
	//如果是在反匯編窗口中點擊
	if (origin == PM_DISASM) {
		switch (action)
		{
		case 0:
			RenameCall((t_dump*)item);
			break;
		}
	}

	if (origin == PM_MAIN) {
		switch (action)
		{
		case 0: {
			flag = true;
			Go(0, 0, STEP_OVER, 0, 0);
			break;
		}
		}
	}

}



