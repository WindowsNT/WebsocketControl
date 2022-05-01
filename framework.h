// header.h : include file for standard system include files,
// or project specific include files
//

#pragma once

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <WinSock2.h>
#include <windows.h>
// C RunTime Header Files
#include <stdlib.h>
#include <string>
#include <memory>
#include <vector>
#include <sstream>
#include <mutex>
#include <malloc.h>
#include <functional>
#include <map>
#include <thread>
#include <memory.h>
#include <iphlpapi.h>
#include <tchar.h>
#include <websocket.h>
#include <shlobj.h>
#include <shellapi.h>
#include <UPnP.h>
#include <natupnp.h>
#include <WinDNS.h>
#include <wincrypt.h>
#include <commctrl.h>

#include "mime2.h"
#include "socket.h"
