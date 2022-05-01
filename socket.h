#pragma once
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>


class XSOCKET
{
protected:
	SOCKET X = 0;
	int fam = 0;
	std::shared_ptr<int> ptr;


public:



	bool Valid()
	{
		if (X == 0 || X == -1)
			return false;
		return true;
	}

	void CloseIf()
	{
		if (ptr.use_count() == 1)
			Close();
	}

	SOCKET h()
	{
		return X;
	}

	operator SOCKET()
	{
		return X;
	}

	~XSOCKET()
	{
		CloseIf();
	}


	XSOCKET(SOCKET t)
	{
		operator =(t);
	}

	void operator =(SOCKET t)
	{
		Close();
		X = t;
		ptr = std::make_shared<int>(int(0));
	}


	XSOCKET(const XSOCKET& x)
	{
		operator =(x);
	}

	XSOCKET& operator =(const XSOCKET& x)
	{
		CloseIf();
		ptr = x.ptr;
		X = x.X;
		return *this;
	}


	XSOCKET(int af = AF_INET, int ty = SOCK_STREAM, int pro = IPPROTO_TCP)
	{
		if (af == 0)
			return;
		Create(af, ty, pro);
	}

	void Create(int af = AF_INET, int ty = SOCK_STREAM, int pro = IPPROTO_TCP)
	{
		fam = af;
		X = socket(af, ty, pro);
		if (X == 0 || X == INVALID_SOCKET)
		{
//			int ws = WSAGetLastError();
			X = 0;
			return;
		}
		if (af == AF_INET6)
		{
			DWORD ag = 0;
			setsockopt(X, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ag, 4);
		}
		ptr = std::make_shared<int>(int(0));
	}

	void Detach()
	{
		X = 0;
	}

	void Close()
	{
		if (X != INVALID_SOCKET && X != 0)
			closesocket(X);
		X = 0;
	}

	bool Bind(int port)
	{
		if (fam == AF_INET6)
		{
			sockaddr_in6 sA = { 0 };
			sA.sin6_family = (ADDRESS_FAMILY)fam;
			sA.sin6_port = (u_short)htons((u_short)port);
			if (::bind(X, (sockaddr*)&sA, sizeof(sA)) < 0)
				return false;

		}
		else
		{
			sockaddr_in sA = { 0 };
			sA.sin_addr.s_addr = INADDR_ANY;
			sA.sin_family = (ADDRESS_FAMILY)fam;
			sA.sin_port = (u_short)htons((u_short)port);
			if (::bind(X, (sockaddr*)&sA, sizeof(sA)) < 0)
				return false;
		}
		return true;
	}

	bool BindAndListen(int port)
	{
		if (!Bind(port))
			return false;
		listen(X, 3);
		return true;
	}

	SOCKET Accept()
	{
		return accept(X, 0, 0);
	}


	BOOL ConnectTo(const char* addr, int port, int sec = 0, std::tuple<std::wstring, int, int> proxy = std::make_tuple<>(L"", 0, 0))
	{
		// Check the address
		if (!addr || !port)
			return false;
		wchar_t se[100] = { 0 };
		swprintf_s(se, 100, L"%u", port);
		timeval tv = { 0 };
		tv.tv_sec = sec;
		wchar_t adr[1000] = { 0 };
		MultiByteToWideChar(CP_UTF8,0,addr,-1,adr,1000);
//		wcscpy_s(adr, 1000, UWL::ystring(addr));
		if (std::get<1>(proxy) == 0)
			return WSAConnectByName(X, adr, se, 0, 0, 0, 0, sec ? &tv : 0, 0);

		swprintf_s(se, 100, L"%u", std::get<1>(proxy));
		BOOL Rx = WSAConnectByName(X, (LPWSTR)std::get<0>(proxy).c_str(), se, 0, 0, 0, 0, sec ? &tv : 0, 0);
		if (!Rx)
			return FALSE;

		// Try the proxy connection
		if (std::get<2>(proxy) == 5)
		{
			// SOCKS 5
			// A - Send 0x05 0x02 0x00 0x02
			//     or 0x05 0x01 0x00 if we have no uid/pwd
			const char* a1 = "\x05\x01\x00";
			transmit(a1, 3, true);
			char r1[2];
			receive(r1, 2, true);
			if (r1[0] != 5) return FALSE;
			if (r1[1] != 0) return FALSE;

			// Send request
			/*
			+----+-----+-------+------+----------+----------+
			|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+
			*/

			char b[1000] = { 0 };
			b[0] = 5;
			b[1] = 1; // Connect
			b[2] = 0; // R
			b[3] = 3; // Domain name
			b[4] = (char)strlen(addr);
			strcpy_s(b + 5, 995, addr);
			short p2 = htons((short)port);
			memcpy(b + 5 + strlen(addr), &p2, 2);

			int ts = 5 + (int)strlen(addr) + 2;
			transmit(b, ts, true);

			/*

			+----+-----+-------+------+----------+----------+
			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+


			*/
			char saddr[100];
			int rv = receive(saddr, 4, true);
			if (rv != 4)
				return FALSE;
			if (saddr[1] != 0)
				return FALSE;

			// Success! Get stuff out of our way
			if (saddr[3] == '\x01')
				receive(saddr, 6, true);
			else
				if (saddr[3] == '\x04')
					receive(saddr, 18, true);

			return TRUE;

		}


		/*
		//	ADDRINFO h1;
		ADDRINFO* h2 = 0;
		char po[100] = { 0 };
		sprintf_s(po, 100, "%u", port);
		getaddrinfo(addr, po, 0, &h2);
		if (!h2)
			return false;

		if (X == INVALID_SOCKET || X == 0)
			return 0;

		if (connect(X, (sockaddr*)h2->ai_addr, (int)h2->ai_addrlen) < 0)
			return false;
		return true;
		*/

		return TRUE;
	}


	int utransmit(char *b, int sz)
	{
		return sendto(X, b, sz, 0, 0, 0);
	}

	int ureceive(char* b, int sz)
	{
		return recvfrom(X, b, sz, 0,0,0);
	}
	
	int transmit(const char *b, int sz, bool ForceAll = false, int p = 0, std::function<void(int)> cb = nullptr)
	{
		// same as send, but forces reading ALL sz
		if (!ForceAll)
			return send(X, b, sz, p);
		int rs = 0;
		for (;;)
		{
			int tosend = sz - rs;
			if (tosend > 10000)
				tosend = 10000;
			int rval = send(X, b + rs, tosend, p);
			if (rval == 0 || rval == SOCKET_ERROR)
			{
				auto err = WSAGetLastError();
				err;
				return rs;
			}
			rs += rval;
			if (cb)
				cb(rs);
			if (rs == sz)
				return rs;
		}
	}


	int receive(char *b, int sz, bool ForceAll = false, int p = 0)
	{
		// same as recv, but forces reading ALL sz
		if (!ForceAll)
			return recv(X, b, sz, p);
		int rs = 0;
		for (;;)
		{
			int rval = recv(X, b + rs, sz - rs, p);
			if (rval == 0 || rval == SOCKET_ERROR)
				return rs;
			rs += rval;
			if (rs == sz)
				return rs;
		}
	}





};

typedef void(__stdcall *sscb)(SOCKET X, unsigned long long cur, unsigned long long max, unsigned long long lparam);
class SSL_SOCKET_CALLBACK
{
public:

	sscb scb = 0;
	unsigned long long lparam = 0;
};

class SSL_SOCKET : public XSOCKET
{
private:

	int Type = 0;
	HCERTSTORE hCS = 0;
	SCHANNEL_CRED m_SchannelCred = {  };
	CredHandle hCred = {};
	CtxtHandle hCtx = {};
	std::wstring dn;
	SecBufferDesc sbin = {};
	SecBufferDesc sbout = {};
	bool InitContext = 0;
	std::vector<char> ExtraData;
	std::vector<char> PendingRecvData;
	PCCERT_CONTEXT OurCertificate = 0;
	bool IsExternalCert = 0;


public:

	void SetType(int ty)
	{
		Type = ty;
	}

	SSL_SOCKET(int af = AF_INET, int ty = 0, PCCERT_CONTEXT pc = 0) : XSOCKET(af)
	{
		Type = ty;
		hCred.dwLower = 0;
		hCred.dwUpper = 0;
		hCtx.dwLower = 0;
		hCtx.dwUpper = 0;
		if (pc)
		{
			OurCertificate = pc;
			IsExternalCert = true;
		}
	}

	~SSL_SOCKET()
	{
		if (Type == 0)
			ClientOff();
		else
			ServerOff();

		if (hCtx.dwLower || hCtx.dwUpper)
			DeleteSecurityContext(&hCtx);

		if (hCred.dwLower || hCred.dwUpper)
			FreeCredentialHandle(&hCred);

		if (OurCertificate && !IsExternalCert)
		{
			CertFreeCertificateContext(OurCertificate);
			OurCertificate = 0;
		}

		if (hCS)
			CertCloseStore(hCS, 0);
		hCS = 0;
	}

	void SetDestinationName(const wchar_t* n)
	{
		dn = n;
	}

	int ClientOff()
	{
		// Client wants to disconnect
		SECURITY_STATUS ss = 0;
		std::vector<SecBuffer> OutBuffers(100);
		DWORD dwType = SCHANNEL_SHUTDOWN;
		OutBuffers[0].pvBuffer = &dwType;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer = sizeof(dwType);

		sbout.cBuffers = 1;
		sbout.pBuffers = OutBuffers.data();
		sbout.ulVersion = SECBUFFER_VERSION;

		for (;;)
		{
			ss = ApplyControlToken(&hCtx, &sbout);
			if (FAILED(ss))
				return -1;

			DWORD dwSSPIFlags = 0;
			DWORD dwSSPIOutFlags = 0;
			dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

			OutBuffers[0].pvBuffer = NULL;
			OutBuffers[0].BufferType = SECBUFFER_TOKEN;
			OutBuffers[0].cbBuffer = 0;
			sbout.cBuffers = 1;
			sbout.pBuffers = OutBuffers.data();
			sbout.ulVersion = SECBUFFER_VERSION;

			ss = InitializeSecurityContext(&hCred, &hCtx, NULL, dwSSPIFlags, 0, SECURITY_NATIVE_DREP, NULL, 0, &hCtx, &sbout, &dwSSPIOutFlags, 0);
			if (FAILED(ss))
				return -1;

			PBYTE pbMessage = 0;
			DWORD cbMessage = 0;
			pbMessage = (BYTE *)(OutBuffers[0].pvBuffer);
			cbMessage = OutBuffers[0].cbBuffer;

			if (pbMessage != NULL && cbMessage != 0)
			{
				int rval = transmit((char*)pbMessage, cbMessage, true);
				FreeContextBuffer(pbMessage);
				return rval;
			}
			break;
		}
		return 1;
	}

	int ServerOff()
	{
		// Server wants to disconnect
		SECURITY_STATUS ss;
		std::vector<SecBuffer> OutBuffers(100);
		DWORD dwType = SCHANNEL_SHUTDOWN;
		OutBuffers[0].pvBuffer = &dwType;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer = sizeof(dwType);

		sbout.cBuffers = 1;
		sbout.pBuffers = OutBuffers.data();
		sbout.ulVersion = SECBUFFER_VERSION;

		for (;;)
		{
			ss = ApplyControlToken(&hCtx, &sbout);
			if (FAILED(ss))
				return -1;

			DWORD dwSSPIFlags = 0;
			DWORD dwSSPIOutFlags = 0;
			dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

			OutBuffers[0].pvBuffer = NULL;
			OutBuffers[0].BufferType = SECBUFFER_TOKEN;
			OutBuffers[0].cbBuffer = 0;
			sbout.cBuffers = 1;
			sbout.pBuffers = OutBuffers.data();
			sbout.ulVersion = SECBUFFER_VERSION;

			ss = AcceptSecurityContext(&hCred, &hCtx, NULL, dwSSPIFlags, SECURITY_NATIVE_DREP, NULL, &sbout, &dwSSPIOutFlags, 0);
			if (FAILED(ss))
				return -1;

			PBYTE pbMessage = 0;
			DWORD cbMessage = 0;
			pbMessage = (BYTE *)(OutBuffers[0].pvBuffer);
			cbMessage = OutBuffers[0].cbBuffer;

			if (pbMessage != NULL && cbMessage != 0)
			{
				int rval = transmit((char*)pbMessage, cbMessage, true);
				FreeContextBuffer(pbMessage);
				return rval;
			}
			break;
		}
		return 1;
	}

	int sreceive(char* b, int sz, int fall, SSL_SOCKET_CALLBACK* ssc)
	{
		int rs = 0;
		for (;;)
		{
			int rval = s_recv(b + rs, sz - rs);
			if (rval == 0 || rval == SOCKET_ERROR)
				return rs;
			rs += rval;
			if (ssc)
			{
				if (ssc->scb)
				{
					ssc->scb(0, rs, sz, ssc->lparam);
				}
			}
			if (rs == sz || fall == 0)
				return rs;
		}
	}


	int s_recv(char* b, unsigned  int sz, std::vector<char>* encr = 0)
	{
		SecPkgContext_StreamSizes Sizes;
		SECURITY_STATUS ss = 0;
		ss = QueryContextAttributes(&hCtx, SECPKG_ATTR_STREAM_SIZES, &Sizes);
		if (FAILED(ss))
			return -1;

		unsigned int TotalR = 0;
		int pI = 0;
		SecBuffer Buffers[5] = { 0 };
		SecBuffer *     pDataBuffer;
		SecBuffer *     pExtraBuffer;
		std::vector<char> mmsg(Sizes.cbMaximumMessage * 2);

		if (PendingRecvData.size())
		{
			if (sz <= PendingRecvData.size())
			{
				memcpy(b, PendingRecvData.data(), sz);
				std::vector<char> dj(PendingRecvData.size() - sz);
				memcpy(dj.data(), PendingRecvData.data() + sz, PendingRecvData.size() - sz);
				PendingRecvData = dj;
				return sz;
			}
			// else , occupied already
			memcpy(b, PendingRecvData.data(), PendingRecvData.size());
			sz = (unsigned int)PendingRecvData.size();
			PendingRecvData.clear();
			return sz;
		}

		for (;;)
		{
			unsigned int dwMessage = Sizes.cbMaximumMessage;

			if (dwMessage > Sizes.cbMaximumMessage)
				dwMessage = Sizes.cbMaximumMessage;

			int rval = 0;
			if (ExtraData.size())
			{
				memcpy(mmsg.data() + pI, ExtraData.data(), ExtraData.size());
				pI += (unsigned int)ExtraData.size();
				ExtraData.clear();
			}
			else
			{
				if (encr)
				{
					memcpy(mmsg.data() + pI, encr->data(), encr->size());
					rval = (int)encr->size();
				}
				else
				{
					rval = receive_raw(mmsg.data() + pI, dwMessage);
				}
				if (rval == 0 || rval == -1)
					return rval;
				pI += rval;
			}


			Buffers[0].pvBuffer = mmsg.data();
			Buffers[0].cbBuffer = pI;
			Buffers[0].BufferType = SECBUFFER_DATA;

			Buffers[1].BufferType = SECBUFFER_EMPTY;
			Buffers[2].BufferType = SECBUFFER_EMPTY;
			Buffers[3].BufferType = SECBUFFER_EMPTY;

			sbin.ulVersion = SECBUFFER_VERSION;
			sbin.pBuffers = Buffers;
			sbin.cBuffers = 4;

			ss = DecryptMessage(&hCtx, &sbin, 0, NULL);
			if (ss == SEC_E_INCOMPLETE_MESSAGE)
				continue;
			if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE && ss != SEC_I_CONTEXT_EXPIRED)
				return -1;

			pDataBuffer = NULL;
			pExtraBuffer = NULL;
			for (int i = 0; i < 4; i++)
			{
				if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
				{
					pDataBuffer = &Buffers[i];
				}
				if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
				{
					pExtraBuffer = &Buffers[i];
				}
			}
			if (pExtraBuffer)
			{
				ExtraData.resize(pExtraBuffer->cbBuffer);
				memcpy(ExtraData.data(), pExtraBuffer->pvBuffer, ExtraData.size());
				pI = 0;
			}

			if (ss == SEC_I_RENEGOTIATE)
			{
				ss = ClientLoop();
				if (FAILED(ss))
					return -1;
			}



			if (pDataBuffer == 0)
				break;
			else if ((pDataBuffer->cbBuffer == 0) && ExtraData.size())
			{
				// BUG under Windows 7/Server 2008
				// DecryptMessage needs to be called a second time
				// in order to get the plain data
				continue;
			}

			TotalR = pDataBuffer->cbBuffer;
			if (TotalR <= sz)
			{
				memcpy(b, pDataBuffer->pvBuffer, TotalR);
			}
			else
			{
				TotalR = sz;
				memcpy(b, pDataBuffer->pvBuffer, TotalR);
				PendingRecvData.resize(pDataBuffer->cbBuffer - TotalR);
				memcpy(PendingRecvData.data(), (char*)pDataBuffer->pvBuffer + TotalR, PendingRecvData.size());
			}


			break;
		}



		return TotalR;
	}

	int transmit_raw(char *b, int sz, bool ForceAll = false, int p = 0, std::function<void(int)> cb = nullptr)
	{
		return XSOCKET::transmit(b, sz, ForceAll, p, cb);
	}

	int transmit(char *b, int sz, bool ForceAll = false, int p = 0, std::function<void(int)> cb = nullptr)
	{
		UNREFERENCED_PARAMETER(p);
		UNREFERENCED_PARAMETER(ForceAll);
		return stransmit(b, sz);
	}

	int receive(char *b, int sz, bool ForceAll = false, int p = 0)
	{
		UNREFERENCED_PARAMETER(p);
		UNREFERENCED_PARAMETER(ForceAll);
		return sreceive(b, sz, ForceAll, 0);
	}

	int receive_raw(char *b, int sz, bool ForceAll = false, int p = 0)
	{
		return XSOCKET::receive(b, sz, ForceAll, p);
	}

	int stransmit(const char* b, int sz, std::vector<char>* rm = 0)
	{
		// QueryContextAttributes
		// Encrypt Message
		// ssend

		SecPkgContext_StreamSizes Sizes = { 0 };
		SECURITY_STATUS ss = 0;
		ss = QueryContextAttributes(&hCtx, SECPKG_ATTR_STREAM_SIZES, &Sizes);
		if (FAILED(ss))
			return -1;

		std::vector<SecBuffer> Buffers(100);
		int mPos = 0;
		for (;;)
		{
			std::vector<char> mmsg(Sizes.cbMaximumMessage * 2);
			std::vector<char> mhdr(Sizes.cbHeader * 2);
			std::vector<char> mtrl(Sizes.cbTrailer * 2);

			unsigned int dwMessage = sz - mPos;
			if (dwMessage == 0)
				break; // all ok!

			if (dwMessage > Sizes.cbMaximumMessage)
			{
				dwMessage = Sizes.cbMaximumMessage;
			}
			memcpy(mmsg.data(), b + mPos, dwMessage);
			mPos += dwMessage;


			Buffers[0].pvBuffer = mhdr.data();
			Buffers[0].cbBuffer = Sizes.cbHeader;
			Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
			Buffers[2].pvBuffer = mtrl.data();
			Buffers[2].cbBuffer = Sizes.cbTrailer;
			Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
			Buffers[3].pvBuffer = 0;
			Buffers[3].cbBuffer = 0;
			Buffers[3].BufferType = SECBUFFER_EMPTY;
			Buffers[1].pvBuffer = mmsg.data();
			Buffers[1].cbBuffer = dwMessage;
			Buffers[1].BufferType = SECBUFFER_DATA;

			sbin.ulVersion = SECBUFFER_VERSION;
			sbin.pBuffers = Buffers.data();
			sbin.cBuffers = 4;

			ss = EncryptMessage(&hCtx, 0, &sbin, 0);
			if (FAILED(ss))
				return -1;

			if (rm)
			{
				int Total = Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer;
				rm->resize(Total);
				int c = 0;
				memcpy(rm->data() + c, Buffers[0].pvBuffer, Buffers[0].cbBuffer);
				c += Buffers[0].cbBuffer;
				memcpy(rm->data() + c, Buffers[1].pvBuffer, Buffers[1].cbBuffer);
				c += Buffers[1].cbBuffer;
				memcpy(rm->data() + c, Buffers[2].pvBuffer, Buffers[2].cbBuffer);
			}
			else
			{
				// Send this message
				unsigned int rval = (unsigned int)transmit_raw((char*)Buffers[0].pvBuffer, Buffers[0].cbBuffer, true);
				if (rval != Buffers[0].cbBuffer)
					return rval;
				rval = transmit_raw((char*)Buffers[1].pvBuffer, Buffers[1].cbBuffer, true);
				if (rval != Buffers[1].cbBuffer)
					return rval;
				rval = transmit_raw((char*)Buffers[2].pvBuffer, Buffers[2].cbBuffer, true);
				if (rval != Buffers[2].cbBuffer)
					return rval;
			}
		}


		return sz;
	}



	int ClientLoop()
	{
		SECURITY_STATUS ss = SEC_I_CONTINUE_NEEDED;
		std::vector<char> t(0x11000);
		std::vector<SecBuffer> bufsi(100);
		std::vector<SecBuffer> bufso(100);
		int pt = 0;

		// Loop using InitializeSecurityContext until success
		for (;;)
		{
			if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_INCOMPLETE_MESSAGE && ss != SEC_I_INCOMPLETE_CREDENTIALS)
				break;

			DWORD dwSSPIFlags =
				ISC_REQ_SEQUENCE_DETECT |
				ISC_REQ_REPLAY_DETECT |
				ISC_REQ_CONFIDENTIALITY |
				ISC_RET_EXTENDED_ERROR |
				ISC_REQ_ALLOCATE_MEMORY |
				ISC_REQ_STREAM;

			dwSSPIFlags |= ISC_REQ_MANUAL_CRED_VALIDATION;

			if (InitContext == 0)
			{
				// Initialize sbout
				bufso[0].pvBuffer = NULL;
				bufso[0].BufferType = SECBUFFER_TOKEN;
				bufso[0].cbBuffer = 0;
				sbout.ulVersion = SECBUFFER_VERSION;
				sbout.cBuffers = 1;
				sbout.pBuffers = bufso.data();
			}
			else
			{
				// Get Some data from the remote site

				// Add also extradata?
				if (ExtraData.size())
				{
					memcpy(t.data(), ExtraData.data(), ExtraData.size());
					pt += (unsigned int)ExtraData.size();
					ExtraData.clear();
				}


				int rval = recv(X, t.data() + pt, 0x10000, 0);
				if (rval == 0 || rval == -1)
					return rval;
				pt += rval;

				// Put this data into the buffer so InitializeSecurityContext will do

				bufsi[0].BufferType = SECBUFFER_TOKEN;
				bufsi[0].cbBuffer = pt;
				bufsi[0].pvBuffer = t.data();
				bufsi[1].BufferType = SECBUFFER_EMPTY;
				bufsi[1].cbBuffer = 0;
				bufsi[1].pvBuffer = 0;
				sbin.ulVersion = SECBUFFER_VERSION;
				sbin.pBuffers = bufsi.data();
				sbin.cBuffers = 2;

				bufso[0].pvBuffer = NULL;
				bufso[0].BufferType = SECBUFFER_TOKEN;
				bufso[0].cbBuffer = 0;
				sbout.cBuffers = 1;
				sbout.pBuffers = bufso.data();
				sbout.ulVersion = SECBUFFER_VERSION;

			}

			DWORD dwSSPIOutFlags = 0;

			SEC_E_INTERNAL_ERROR;
			ss = InitializeSecurityContext(
				&hCred,
				InitContext ? &hCtx : 0,
				(SEC_WCHAR*)dn.c_str(),
				dwSSPIFlags,
				0,
				0,//SECURITY_NATIVE_DREP,
				InitContext ? &sbin : 0,
				0,
				InitContext ? 0 : &hCtx,
				&sbout,
				&dwSSPIOutFlags,
				0);

			if (ss == SEC_E_INCOMPLETE_MESSAGE)
				continue; // allow more

			pt = 0;

			if (FAILED(ss))
				return -1;

			if (InitContext == 0 && ss != SEC_I_CONTINUE_NEEDED)
				return -1;

			// Handle possible ExtraData
			if (bufsi[1].BufferType == SECBUFFER_EXTRA)
			{
				SecBuffer& bu = bufsi[1];
				SecBuffer& bu0 = bufsi[0];
				ExtraData.resize(bu.cbBuffer);

				if (bu.pvBuffer)
					memcpy(ExtraData.data(), bu.pvBuffer, ExtraData.size());
				else
					if (bu0.pvBuffer && bu0.cbBuffer >= ExtraData.size())
					{
						memcpy(ExtraData.data(), (char*)bu0.pvBuffer + (bu0.cbBuffer - ExtraData.size()), ExtraData.size());
					}
			}


			if (!InitContext)
			{
				// Send the data we got to the remote part
				//cbData = Send(OutBuffers[0].pvBuffer,OutBuffers[0].cbBuffer);
				unsigned int rval = (unsigned int)transmit_raw((char*)bufso[0].pvBuffer, bufso[0].cbBuffer, true);
				FreeContextBuffer(bufso[0].pvBuffer);
				if (rval != bufso[0].cbBuffer)
					return -1;
				InitContext = true;
				continue;
			}

			// Pass data to the remote site
			unsigned int rval = (unsigned int)transmit_raw((char*)bufso[0].pvBuffer, bufso[0].cbBuffer, true);
			FreeContextBuffer(bufso[0].pvBuffer);
			if (rval != bufso[0].cbBuffer)
				return -1;


			if (ss == S_OK)
				break; // wow!!

		}
		return 0;
	}



	void NoFail(HRESULT hr)
	{
		if (FAILED(hr))
			throw;
	}

	PCCERT_CONTEXT CreateOurCertificate()
	{
		// CertCreateSelfSignCertificate(0,&SubjectName,0,0,0,0,0,0);
		HRESULT hr = 0;
		HCRYPTPROV hProv = NULL;
		PCCERT_CONTEXT p = 0;
		HCRYPTKEY hKey = 0;
		CERT_NAME_BLOB sib = { 0 };
		BOOL AX = 0;

		// Step by step to create our own certificate
		try
		{
			// Create the subject
			char cb[1000] = { 0 };
			sib.pbData = (BYTE*)cb;
			sib.cbData = 1000;
			const wchar_t*	szSubject = L"CN=Certificate";
			if (!CertStrToName(CRYPT_ASN_ENCODING, szSubject, 0, 0, sib.pbData, &sib.cbData, NULL))
				throw;


			// Acquire Context
			const wchar_t* pszKeyContainerName = L"Container";

			if (!CryptAcquireContext(&hProv, pszKeyContainerName, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
			{
				hr = GetLastError();
				if (GetLastError() == NTE_EXISTS)
				{
					if (!CryptAcquireContext(&hProv, pszKeyContainerName, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))
					{
						throw;
					}
				}
				else
					throw;
			}

			// Generate KeyPair
			if (!CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey))
				throw;

			// Generate the certificate
			CRYPT_KEY_PROV_INFO kpi = { 0 };
			kpi.pwszContainerName = (LPWSTR)pszKeyContainerName;
			kpi.pwszProvName = (LPWSTR)MS_DEF_PROV;
			kpi.dwProvType = PROV_RSA_FULL;
			kpi.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
			kpi.dwKeySpec = AT_KEYEXCHANGE;

			SYSTEMTIME et;
			GetSystemTime(&et);
			et.wYear += 1;

			CERT_EXTENSIONS exts = { 0 };
			p = CertCreateSelfSignCertificate(hProv, &sib, 0, &kpi, NULL, NULL, &et, &exts);

			if (p)
				AX = CryptFindCertificateKeyProvInfo(p, CRYPT_FIND_MACHINE_KEYSET_FLAG, NULL);
		}

		catch (...)
		{
		}

		if (hKey)
			CryptDestroyKey(hKey);
		hKey = 0;

		if (hProv)
			CryptReleaseContext(hProv, 0);
		hProv = 0;
		return p;
	}

	int ServerInit(bool NoLoop = false)
	{
		SECURITY_STATUS ss = 0;
		if (IsExternalCert)
		{
			;
		}
		else
		{
			//BOOL AX;
			OurCertificate = CreateOurCertificate();
		}

		// Configure our SSL SChannel
		memset(&m_SchannelCred, 0, sizeof(m_SchannelCred));
		m_SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
		m_SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
		m_SchannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_REVOCATION_CHECK_CHAIN;
		m_SchannelCred.hRootStore = hCS;
		m_SchannelCred.dwMinimumCipherStrength = 128;

		if (OurCertificate)
		{
			m_SchannelCred.cCreds = 1;
			m_SchannelCred.paCred = &OurCertificate;
		}

		ss = AcquireCredentialsHandle(0, (LPWSTR)SCHANNEL_NAME, SECPKG_CRED_INBOUND, 0, &m_SchannelCred, 0, 0, &hCred, 0);
		if (FAILED(ss))
			return -1;
		if (NoLoop)
			return 0;
		return ServerLoop();
	}

	int ClientInit(bool NoLoop = false)
	{
		SECURITY_STATUS ss = 0;
		if (IsExternalCert)
		{
			;
		}
		else
		{
			OurCertificate = CreateOurCertificate();
		}

		// Configure our SSL SChannel
		memset(&m_SchannelCred, 0, sizeof(m_SchannelCred));
		m_SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
		m_SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
		m_SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_REVOCATION_CHECK_CHAIN;

		if (OurCertificate)
		{
			m_SchannelCred.cCreds = 1;
			m_SchannelCred.paCred = &OurCertificate;
		}

		ss = AcquireCredentialsHandle(0, (LPWSTR)SCHANNEL_NAME, SECPKG_CRED_OUTBOUND, 0, &m_SchannelCred, 0, 0, &hCred, 0);
		if (FAILED(ss))
			return 0;

		if (NoLoop)
			return 0;
		return ClientLoop();
	}

	int ServerLoop()
	{
		// Loop AcceptSecurityContext
		SECURITY_STATUS ss = SEC_I_CONTINUE_NEEDED;
		std::vector<char> t(0x11000);
		std::vector<SecBuffer> bufsi(100);
		std::vector<SecBuffer> bufso(100);
		int pt = 0;

		// Loop using InitializeSecurityContext until success
		for (;;)
		{
			if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_INCOMPLETE_MESSAGE && ss != SEC_I_INCOMPLETE_CREDENTIALS)
				break;

			DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
				ISC_REQ_REPLAY_DETECT |
				ISC_REQ_CONFIDENTIALITY |
				ISC_RET_EXTENDED_ERROR |
				ISC_REQ_ALLOCATE_MEMORY |
				ISC_REQ_STREAM;

			dwSSPIFlags |= ISC_REQ_MANUAL_CRED_VALIDATION;

			// Get Some data from the remote site
			int rval = recv(X, t.data() + pt, 0x10000, 0);
			if (rval == 0 || rval == -1)
				return -1;
			pt += rval;

			// Put this data into the buffer so InitializeSecurityContext will do
			bufsi[0].BufferType = SECBUFFER_TOKEN;
			bufsi[0].cbBuffer = pt;
			bufsi[0].pvBuffer = t.data();
			bufsi[1].BufferType = SECBUFFER_EMPTY;
			bufsi[1].cbBuffer = 0;
			bufsi[1].pvBuffer = 0;
			sbin.ulVersion = SECBUFFER_VERSION;
			sbin.pBuffers = bufsi.data();
			sbin.cBuffers = 2;

			bufso[0].pvBuffer = NULL;
			bufso[0].BufferType = SECBUFFER_TOKEN;
			bufso[0].cbBuffer = 0;
			bufso[1].BufferType = SECBUFFER_EMPTY;
			bufso[1].cbBuffer = 0;
			bufso[1].pvBuffer = 0;
			sbout.cBuffers = 2;
			sbout.pBuffers = bufso.data();
			sbout.ulVersion = SECBUFFER_VERSION;


			SEC_E_INTERNAL_ERROR;
			DWORD flg = 0;
			ss = AcceptSecurityContext(
				&hCred,
				InitContext ? &hCtx : 0,
				&sbin,
				ASC_REQ_ALLOCATE_MEMORY, 0,
				InitContext ? 0 : &hCtx,
				&sbout,
				&flg,
				0);

			InitContext = true;

			if (ss == SEC_E_INCOMPLETE_MESSAGE)
				continue; // allow more

			pt = 0;

			if (FAILED(ss))
				return -1;

			if (InitContext == 0 && ss != SEC_I_CONTINUE_NEEDED)
				return -1;

			// Pass data to the remote site
			unsigned int rval2 = (unsigned int)transmit((char*)bufso[0].pvBuffer, bufso[0].cbBuffer, true);
			FreeContextBuffer(bufso[0].pvBuffer);
			if (rval2 != bufso[0].cbBuffer)
				return -1;

			if (ss == S_OK)
				break; // wow!!

		}
		return 0;
	}





};


// Socket stuff
inline int rrecv(SOCKET s, char *b, int sz, int p = 0)
{
	// same as recv, but forces reading ALL sz
	int rs = 0;
	for (;;)
	{
		int rval = recv(s, b + rs, sz - rs, p);
		if (rval == 0 || rval == SOCKET_ERROR)
			return rs;
		rs += rval;
		if (rs == sz)
			return rs;
	}
}

inline int ssend(SOCKET s, char *b, int sz, int p = 0)
{
	// same as send, but forces reading ALL sz
	int rs = 0;
	for (;;)
	{
		int tosend = sz - rs;
		if (tosend > 10000)
			tosend = 10000;
		int rval = send(s, b + rs, tosend, p);
		if (rval == 0 || rval == SOCKET_ERROR)
			return rs;
		rs += rval;
		if (rs == sz)
			return rs;
	}
}


