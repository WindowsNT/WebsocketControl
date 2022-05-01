// WebInterface.cpp : Defines the entry point for the application.
//

#include "framework.h"


// ------- Variables
int Port = 12345;
int WebSocketPort = 12347;
std::string host4 = "";
std::string host6 = "";
// -----------------

// Gets all IP addresses and picks the first for IPv4 and IPv6
void PickIP()
{
    std::vector<std::string> ipAddrs;

    ipAddrs.clear();
    using namespace std;
    std::vector<IP_ADAPTER_ADDRESSES> adapter_addresses(100);
    IP_ADAPTER_ADDRESSES* adapter(NULL);

    // Start with a 16 KB buffer and resize if needed -
    // multiple attempts in case interfaces change while
    // we are in the middle of querying them.
    ULONG bs = (ULONG)adapter_addresses.size() * sizeof(IP_ADAPTER_ADDRESSES);
    DWORD error = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME,
        NULL,
        adapter_addresses.data(),
        &bs);

    if (error != ERROR_SUCCESS)
        return; // duh

    // Iterate through all of the adapters
    for (auto adapter = &adapter_addresses[0]; NULL != adapter; adapter = adapter->Next)
    {
        // Skip loopback adapters
        if (IF_TYPE_SOFTWARE_LOOPBACK == adapter->IfType)
            continue;

        // Parse all IPv4 and IPv6 addresses
        for (
            IP_ADAPTER_UNICAST_ADDRESS* address = adapter->FirstUnicastAddress;
            NULL != address;
            address = address->Next)
        {
            auto family = address->Address.lpSockaddr->sa_family;
            if (AF_INET == family)
            {
                // IPv4
                SOCKADDR_IN* ipv4 = reinterpret_cast<SOCKADDR_IN*>(address->Address.lpSockaddr);

                char str_buffer[INET_ADDRSTRLEN] = { 0 };
                inet_ntop(AF_INET, &(ipv4->sin_addr), str_buffer, INET_ADDRSTRLEN);
                if (strstr(str_buffer, "169.254.") == 0)
                    ipAddrs.push_back(str_buffer);
            }
            else if (AF_INET6 == family)
            {
                // IPv6
                SOCKADDR_IN6* ipv6 = reinterpret_cast<SOCKADDR_IN6*>(address->Address.lpSockaddr);

                char str_buffer[INET6_ADDRSTRLEN] = { 0 };
                inet_ntop(AF_INET6, &(ipv6->sin6_addr), str_buffer, INET6_ADDRSTRLEN);

                std::string ipv6_str(str_buffer);

                // Detect and skip non-external addresses
                bool is_link_local(false);
                bool is_special_use(false);

                if (0 == ipv6_str.find("fe"))
                {
                    char c = ipv6_str[2];
                    if (c == '8' || c == '9' || c == 'a' || c == 'b')
                    {
                        is_link_local = true;
                    }
                }
                else if (0 == ipv6_str.find("2001:0:"))
                {
                    is_special_use = true;
                }

                if (!(is_link_local || is_special_use))
                {
                    ipAddrs.push_back(ipv6_str);
                }
            }
            else
            {
                // Skip all other types of addresses
                continue;
            }
        }
    }
    for (auto& e : ipAddrs)
    {
        if (strchr(e.c_str(), ':') == 0)
        {
            host4 = e;
            break;
        }
    }
    for (auto& e : ipAddrs)
    {
        if (strchr(e.c_str(), ':'))
        {
            host6 = e;
            break;
        }
    }
}


HWND hMainWindow = 0;


// Class that handles mDNS registration
class DNSRegistration
{
    DNS_SERVICE_REGISTER_REQUEST rd = {};
    DNS_SERVICE_INSTANCE di = {};
    IP6_ADDRESS i6 = {};
    IP4_ADDRESS i4 = {};
    bool Off = 0;

public:

    DNSRegistration()
    {        
        rd = {};
        rd.pServiceInstance = &di;
        rd.unicastEnabled = 0;
        di.pszInstanceName = (LPWSTR)L"app._http._tcp.local";
        di.pszHostName = (LPWSTR)L"myservice.local";
        InetPtonA(AF_INET6, host6.c_str(), (void*)&i6);
        di.ip6Address = &i6;
        InetPtonA(AF_INET, host4.c_str(), (void*)&i4);
        DWORD dword = i4;

        // Hey, this IP4_ADDRESS is different than in_addr
        DWORD new_dword = (dword & 0x000000ff) << 24 | (dword & 0x0000ff00) << 8 |
            (dword & 0x00ff0000) >> 8 | (dword & 0xff000000) >> 24;
        i4 = new_dword;
        di.ip4Address = &i4;
        di.wPort = (WORD)Port;

        rd.Version = DNS_QUERY_REQUEST_VERSION1;
        rd.pRegisterCompletionCallback = [](DWORD Status,
            PVOID pQueryContext,
            PDNS_SERVICE_INSTANCE pInstance)
        {
            DNSRegistration* r = (DNSRegistration*)pQueryContext;
            if (pInstance)
                DnsServiceFreeInstance(pInstance);
            if (r->Off)
                PostMessage(hMainWindow, WM_CLOSE, 0, 0);
        };
        rd.pQueryContext = this;
        auto err = DnsServiceRegister(&rd, 0);
        if (err != DNS_REQUEST_PENDING)
            MessageBeep(0);
    }

    ~DNSRegistration()
    {
        Off = 1;
        DnsServiceDeRegister(&rd, 0);
    }
};

std::shared_ptr<DNSRegistration> dnsreg;

XSOCKET s1; 
XSOCKET s2;

// Quick Load Resource to std::vector<>
HRESULT ExtractResource(HINSTANCE hXX, const TCHAR* Name, const TCHAR* ty, std::vector<char>& data)
{
    HRSRC R = FindResource(hXX, Name, ty);
    if (!R)
        return E_NOINTERFACE;
    HGLOBAL hG = LoadResource(hXX, R);
    if (!hG)
        return E_FAIL;
    DWORD S = SizeofResource(hXX, R);
    char* p = (char*)LockResource(hG);
    if (!p)
    {
        FreeResource(R);
        return E_FAIL;
    }
    data.resize(S);
    memcpy(data.data(), p, S);
    FreeResource(R);
    return S_OK;
}


class WS
{
    WEB_SOCKET_HANDLE h = 0;
    std::recursive_mutex mu;
public:

    // Create a server side websocket handle.
    HRESULT Init()
    {
        auto hr = WebSocketCreateServerHandle(NULL, 0, &h);
        return hr;
    }

    HRESULT ReceiveRequest(char* d, size_t sz, std::vector<char>& out)
    {
        std::lock_guard<std::recursive_mutex> lg(mu);
        HRESULT hr = WebSocketReceive(h, 0, this);
        if (FAILED(hr))
            return hr;
        WEB_SOCKET_BUFFER b0[100] = {};
        ULONG bc = 1;
        WEB_SOCKET_ACTION sa = {};
        WEB_SOCKET_BUFFER_TYPE bt = {};
        PVOID ctx = 0;
        PVOID ac = 0;
        out.clear();
        for (;;)
        {
            hr = WebSocketGetAction(h, WEB_SOCKET_ALL_ACTION_QUEUE, b0, &bc, &sa, &bt, &ctx, &ac);
            if (FAILED(hr))
                return hr;

            int MustSend = 0;
            if (sa == WEB_SOCKET_RECEIVE_FROM_NETWORK_ACTION)
            {
                if (b0[0].Data.ulBufferLength < sz)
                    return E_FAIL;
                memcpy(b0[0].Data.pbBuffer, d, sz);
                MustSend += (int)sz;
            }
            if (sa == WEB_SOCKET_INDICATE_RECEIVE_COMPLETE_ACTION)
            {
                for (size_t i = 0; i < bc; i++)
                {
                    auto c = out.size();
                    out.resize(out.size() + b0[i].Data.ulBufferLength);
                    memcpy(out.data() + c, b0[i].Data.pbBuffer, b0[i].Data.ulBufferLength);
                }
            }
            WebSocketCompleteAction(h, ac, MustSend);
            if (sa == WEB_SOCKET_NO_ACTION)
                break;
        }
        return hr;
    }

    HRESULT SendRequest(const char* d, size_t sz,std::vector<char>& out)
    {
        std::lock_guard<std::recursive_mutex> lg(mu);
        WEB_SOCKET_BUFFER bu;
        bu.Data.pbBuffer = (PBYTE)d;
        bu.Data.ulBufferLength = (ULONG)sz;
        HRESULT hr = WebSocketSend(h, WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, &bu, this);
        if (FAILED(hr))
            return hr;
        WEB_SOCKET_BUFFER b0[100] = {};
        ULONG bc = 1;
        WEB_SOCKET_ACTION sa = {};
        WEB_SOCKET_BUFFER_TYPE bt = {};
        PVOID ctx = 0;
        PVOID ac = 0;
        out.clear();

        for (;;)
        {
            hr = WebSocketGetAction(h, WEB_SOCKET_SEND_ACTION_QUEUE, b0, &bc, &sa, &bt, &ctx, &ac);
            if (FAILED(hr))
                return hr;

            int MustSend = 0;
            if (sa == WEB_SOCKET_SEND_TO_NETWORK_ACTION)
            {
                for (ULONG i = 0; i < bc; i++)
                {
                    auto cs = out.size();
                    out.resize(cs + b0[i].Data.ulBufferLength);
                    memcpy(out.data() + cs, (char*)b0[i].Data.pbBuffer, b0[i].Data.ulBufferLength);
                    MustSend += (int)b0[i].Data.ulBufferLength;
                }
            }
            WebSocketCompleteAction(h, ac, MustSend);
            if (sa == WEB_SOCKET_NO_ACTION)
                break;
        }
        return hr;
    }

    HRESULT PerformHandshake(PWEB_SOCKET_HTTP_HEADER clientHeaders, ULONG clientHeaderCount,std::vector<char>& s)
    {
        std::lock_guard<std::recursive_mutex> lg(mu);
        HRESULT hr = S_OK;
        ULONG serverAdditionalHeaderCount = 0;
        WEB_SOCKET_HTTP_HEADER* serverAdditionalHeaders = NULL;

        // Start a server side of the handshake. Production applications must parse the incoming
        // HTTP request and pass all headers to the function. The function will return an array websocket
        // specific headers that must be added to the outgoing HTTP response.
        hr = WebSocketBeginServerHandshake(
            h,
            NULL,
            NULL,
            0,
            clientHeaders,
            clientHeaderCount,
            &serverAdditionalHeaders,
            &serverAdditionalHeaderCount);
        if (FAILED(hr))
            return hr;

        const char* m1 = "HTTP/1.1 101 Switching Protocols\r\n";
        std::string j = m1;
        std::wstring j2;
        std::vector<char> d;
        std::vector<char> d2;
        for (ULONG c = 0; c < serverAdditionalHeaderCount; c++)
        {
            auto& h = serverAdditionalHeaders[c];
            d.clear();
            d.resize(h.ulNameLength + 1);
            memcpy(d.data(), h.pcName, h.ulNameLength);
            d2.clear();
            d2.resize(h.ulValueLength + 1);
            memcpy(d2.data(), h.pcValue, h.ulValueLength);
            char dx[900] = {};
            sprintf_s(dx,900,"%s: %s\r\n", d.data(), d2.data());
            j += dx;
        }
        j += "\r\n";
        s.resize(j.size());
        memcpy(s.data(), j.data(), j.size());
        hr = WebSocketEndServerHandshake(h);
        if (FAILED(hr))
            return hr;
        return hr;
    }

    void Off()
    {
        WebSocketAbortHandle(h);
        h = 0;
    }

};


void WebServerThread(XSOCKET y)
{
    std::vector<char> b(10000);
    std::vector<char> b3;
    for (;;)
    {
        b.clear();
        b.resize(10000);
        int rval = y.receive(b.data(), 10000);
        if (rval == 0 || rval == -1)
            break;

        MIME2::CONTENT c;
        c.Parse(b.data(), 1);

        // Get /, display 1.html
        std::string host;
        bool v6 = 0;
        for (auto& h : c.GetHeaders())
        {
            if (h.Left() == "Host")
            {
                host = h.Right();
                std::vector<char> h2(1000);
                strcpy_s(h2.data(), 1000, host.c_str());
                auto p2 = strstr(h2.data(), "]:");
                if (p2)
                {
                    *p2 = 0;
                    host = h2.data() + 1;
                    v6 = 1;
                    break;
                }
                auto p = strchr(h2.data(), ':');
                if (p)
                {
                    *p = 0;
                    host = h2.data();
                }
                break;
            }
        }
        const char* m1 = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n";


        b.clear();
        ExtractResource(GetModuleHandle(0), L"D1", L"DATA", b);
        b.resize(b.size() + 1); 
        char* pb = (char*)b.data();

        char b2[200] = {};

        if (v6)
            sprintf_s(b2,200,"ws://[%s]:%i", host.c_str(), WebSocketPort);
        else
            sprintf_s(b2, 200 , "ws://%s:%i", host.c_str(), WebSocketPort);


        b3.resize(b.size() + 1000);
        strcat_s(b3.data(), b3.size(), m1);
        sprintf_s(b3.data() + strlen(b3.data()), b3.size() - strlen(b3.data()), pb, b2);
        char* pb2 = (char*)b3.data();


        y.transmit((char*)pb2, (int)strlen(pb2), true);
        y.Close();
    }
}

void WebServerAccept()
{
    for (;;)
    {
        XSOCKET y = s1.Accept();
        if (y == INVALID_SOCKET || y == 0)
            break; 
        std::thread t(WebServerThread,y);
        t.detach();

    }
}

std::unordered_map<XSOCKET*, WS> Maps;
void WebSocketThread(XSOCKET s)
{
    std::vector<char> r1(10000);
    for (;;)
    {
        int rv = s.receive(r1.data(), 10000);
        if (rv == 0 || rv == -1)
            break;

        std::vector<WEB_SOCKET_HTTP_HEADER> h1;
        MIME2::CONTENT c;
        c.Parse(r1.data(), 1);
        std::string host;
        for (auto& h : c.GetHeaders())
        {
            if (h.IsHTTP())
                continue;
            WEB_SOCKET_HTTP_HEADER j1;
            auto& cleft = h.LeftC();
            j1.pcName = (PCHAR)cleft.c_str();
            j1.ulNameLength = (ULONG)cleft.length();
            auto& cright = h.rights().rawright;
            j1.pcValue = (PCHAR)cright.c_str();
            j1.ulValueLength = (ULONG)cright.length();
            h1.push_back(j1);
        }

        auto& ws2 = Maps[&s];
        if (FAILED(ws2.Init()))
            break;
        std::vector<char> tosend;
        if (FAILED(ws2.PerformHandshake(h1.data(), (ULONG)h1.size(), tosend)))
            break;
        s.transmit(tosend.data(), (int)tosend.size(), true);
        std::vector<char> msg;
        for (;;)
        {
            int rv = s.receive(r1.data(), 10000);
            if (rv == 0 || rv == -1)
                break;

            msg.clear();
            auto hr = ws2.ReceiveRequest(r1.data(), rv, msg);
            if (FAILED(hr))
                break;
            if (msg.size() == 0)
                continue;
            msg.resize(msg.size() + 1);

            MessageBoxA(hMainWindow, msg.data(), "Message", MB_SYSTEMMODAL | MB_APPLMODAL);
        }

    }
}

void WebSocketAccept()
{
    for (;;)
    {
        XSOCKET y = s2.Accept();
        if (y == INVALID_SOCKET || y == 0)
            break;
        Maps[&y].Init();
        std::thread t(WebSocketThread, y);
        t.detach();

    }
}


void StopWebServer()
{
    s1.Close();
    s2.Close();
}
bool StartWebServer()
{
    s1.Create(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (!s1.BindAndListen(Port))
        return false;
    s2.Create(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (!s2.BindAndListen(WebSocketPort))
        return false;
    std::thread t(WebServerAccept);
    t.detach();
    std::thread t2(WebSocketAccept);
    t2.detach();
    return true;
}



int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    WSADATA wData;
    WSAStartup(MAKEWORD(2, 2), &wData);

    TASKDIALOGCONFIG tc = { 0 };
    tc.cbSize = sizeof(tc);
    tc.hwndParent = 0;
    tc.pszWindowTitle = L"Web Interface";
    tc.pszMainInstruction = L"Web Interface";
    tc.pszContent = L"Web Server is stopped.";
    tc.dwCommonButtons = 0;
    tc.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_CAN_BE_MINIMIZED;
    tc.pfCallback = [](HWND     hwnd, UINT     uNotification, WPARAM   wParam, LPARAM   lParam, LONG_PTR) -> HRESULT
    {
        if (uNotification == TDN_HYPERLINK_CLICKED)
        {
            const wchar_t* url = (wchar_t*)lParam;
            if (url)
                ShellExecute(hwnd, L"open", url, 0, 0, 0);
            return S_OK;
        }

        if (uNotification == TDN_CREATED)
        {
            hMainWindow = hwnd;
            // Pick IP
            PickIP();
        }
        if (uNotification == TDN_BUTTON_CLICKED)
        {
            if (wParam == 103 && dnsreg)
            {
                for (auto& m : Maps)
                {
                    std::vector<char> out;
                    m.second.SendRequest("Hello", 5,out);
                    m.first->transmit((char*)out.data(),(int)out.size(),1);

                }
            }

            if (wParam == 101)
            {
                if (!dnsreg)
                {
                    // Web Server start
                    StartWebServer();
                    dnsreg = std::make_shared<DNSRegistration>();
                    std::vector<wchar_t> msg(1000);
                    swprintf_s(msg.data(), 1000, L"Started.\r\n");
                    if (host4.length())
                        swprintf_s(msg.data() + wcslen(msg.data()), 1000 - wcslen(msg.data()), L"<a href=\"http://%S:%i\">http://%S:%i</a>\r\n",host4.c_str(),Port, host4.c_str(), Port);
                    if (host6.length())
                        swprintf_s(msg.data() + wcslen(msg.data()), 1000 - wcslen(msg.data()), L"<a href=\"http://[%S]:%i\">http://[%S]:%i</a>\r\n", host6.c_str(), Port, host6.c_str(), Port);
                    SendMessage(hwnd, TDM_SET_ELEMENT_TEXT, TDE_CONTENT, (LPARAM)msg.data());
                }
            }
            if (wParam == 102)
            {
                // Web Server start
                StopWebServer();
                dnsreg = 0;
                SendMessage(hwnd, TDM_SET_ELEMENT_TEXT, TDE_CONTENT, (LPARAM)L"Web Server is stopped.");
            }

            if (wParam == 199)
                return S_OK;
            return S_FALSE;
        }
        return S_OK;
    };

    TASKDIALOG_BUTTON b[4];
    tc.pButtons = b;
    tc.cButtons = 4;
    b[0].nButtonID = 101;
    b[0].pszButtonText = L"Start";
    b[1].nButtonID = 102;
    b[1].pszButtonText = L"Stop";
    b[2].nButtonID = 103;
    b[2].pszButtonText = L"Send \"Hello\"";
    b[3].nButtonID = 199;
    b[3].pszButtonText = L"Exit";
    int rv = 0;
    BOOL ve = 0;
    TaskDialogIndirect(&tc, &rv, 0, &ve);

    StopWebServer();
    dnsreg = 0;
    Sleep(2000);

    return 0;
}




