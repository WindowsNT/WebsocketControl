#pragma once

#ifdef MIME_ADES
#include "f:\\TOOLS\\AdES\\AdES.hpp"

//#pragma comment(lib,"f:\\tools\\ades\\ades.lib")

/*
#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib,".\\AdES\\ades64d.lib")
#else
#pragma comment(lib,".\\AdES\\ades32d.lib")
#endif
#else
#ifdef _WIN64
#pragma comment(lib,".\\AdES\\ades64r.lib")
#else
#pragma comment(lib,".\\AdES\\ades32r.lib")
#endif
#endif
*/

#endif

namespace MIME2
	{
	class CONTENT;
	class CONTENTBUILDER;
	using namespace std;
	void BuildZ(CONTENT&c1, CONTENT&c2, CONTENT&co, const char* s);


	enum class MIMEERR
		{
		OK = 0,
		INVALID = 1,
		NOTSIGNED = 2,
		ERRSIGN = 3,
		};



	inline std::string Char2Base64(const char *Z, size_t s)
		{
		DWORD da = 0;
		CryptBinaryToString((const BYTE*)Z, (DWORD)s, CRYPT_STRING_BASE64, 0, &da);
		da += 100;
		std::unique_ptr<char> out(new char[da]);
		CryptBinaryToStringA((const BYTE*)Z, (DWORD)s, CRYPT_STRING_BASE64, out.get(), &da);
		return out.get();
		}

	inline void Base64ToChar(const char *Z, size_t s, std::vector<char>& out)
		{
		DWORD dw = 0;
		CryptStringToBinaryA(Z, (DWORD)s, CRYPT_STRING_BASE64, 0, &dw, 0, 0);
		out.resize(dw);
		CryptStringToBinaryA(Z, (DWORD)s, CRYPT_STRING_BASE64, (BYTE*)out.data(), &dw, 0, 0);
		}


	MIMEERR ParseMultipleContent2(const char* d, size_t sz, const char* del, vector<CONTENT>& Result);

	inline void Split(const char*m, char del, vector<string>& result)
		{
		if (!m)
			return;
		std::stringstream ss(m);
		while (ss.good())
			{
			string substr;
			std::getline(ss, substr,del);
			result.push_back(substr);
			}
		}

	inline string& Trim(string& s,int j = 0)
		{
		while (s.length() && (j == 0 || j == 1))
			{
			if (s[s.length() - 1] == ' ' || s[s.length() - 1] == '\r' || s[s.length() - 1] == '\n' || s[s.length() - 1] == '\t')
				s.erase(s.end() - 1);
			else
				break;
			}
		while (s.length() && (j == 0 || j == 2))
			{
			if (s[0] == ' ' || s[0] == '\r' || s[0] == '\n' || s[0] == '\t')
				s.erase(s.begin());
			else
				break;
			}
		return s;
		}

	inline vector<char>& Trim(vector<char>& s, int j = 0)
		{
		while (s.size() && (j == 0 || j == 1))
			{
			if (s[s.size() - 1] == ' ' || s[s.size() - 1] == '\r' || s[s.size() - 1] == '\n' || s[s.size() - 1] == '\t')
				s.erase(s.end() - 1);
			else
				break;
			}
		while (s.size() && (j == 0 || j == 2))
			{
			if (s[0] == ' ' || s[0] == '\r' || s[0] == '\n' || s[0] == '\t')
				s.erase(s.begin());
			else
				break;
			}
		return s;
		}

	inline vector<char>& TrimOnce(vector<char>& s)
		{
		if (s.size())
			{
			if (strncmp(s.data() + s.size() - 2, "\r\n", 2) == 0)
				{
				s.erase(s.end() - 1);
				s.erase(s.end() - 1);
				}
			else
			if (strncmp(s.data() + s.size() - 1, "\n", 1) == 0)
				{
				s.erase(s.end() - 1);
				}
			}
		return s;
		}


	inline void Split(const char*m, const char* del, vector<string>& result)
		{
		if (!m || !del)
			return;
		size_t pos = 0;
		std::string token;
		string delimiter = del;
		string s = m;
		while ((pos = s.find(delimiter)) != std::string::npos) 
			{
			token = s.substr(0, pos);
			result.push_back(token);
			s.erase(0, pos + delimiter.length());
			}
		result.push_back(s);
		}


	inline void BinarySplit(const char*m,size_t sz, const char* del, vector<vector<char>>& result)
		{
		if (!m || !del)
			return;
		size_t pos = 0;
		std::string token;
		string delimiter = del;
		string s;
		s.assign(m, sz);
		while ((pos = s.find(delimiter)) != std::string::npos)
			{
			token = s.substr(0, pos);
			vector<char> res;
			res.resize(token.size());
			memcpy(res.data(), token.data(), token.size());
			result.push_back(res);
			s.erase(0, pos + delimiter.length());
			}

		vector<char> res;
		res.resize(s.size());
		memcpy(res.data(), s.data(), s.size());
		result.push_back(res);
		}

	class HDRSTRING
		{
		vector<string> strs;

		public:


		vector<string>& getstrings() { return strs; }

		string Sub(const char* ga) const
			{
			if (!ga)
				return "";
			for (auto& a : strs)
				{
				const char* f1 = strchr(a.c_str(), '=');
				if (!f1)
					{
					if (_stricmp(a.c_str(), ga) == 0)
						return a;
					continue;
					}
				vector<char> leftpart(f1 - a.c_str() + 10);
				strncpy_s(leftpart.data(), leftpart.size(), a.c_str(), f1 - a.c_str());
				if (_strnicmp(leftpart.data(), ga,strlen(ga)) == 0)
					{
					string r = f1 + 1;
					if (r.length() && r[0] == '\"')
						r.erase(r.begin());
					if (r.length() && r[r.length() - 1] == '\"')
						r.erase(r.end() - 1);
					return r;
					}
				}
			return "";
			}

		string rawright;
		MIMEERR Parse(const char* h)
			{
			if (!h)
				return MIMEERR::INVALID;
			rawright = h;
			strs.clear();
			Split(h, ';',strs);


			for (auto& a : strs)
				{
				Trim(a);
				}
			for (signed long long i = strs.size() - 1 ; i >= 0 ; i--)
				{
				if (strs[(size_t)i].length() == 0)
					strs.erase(strs.begin() + (size_t)i);
				}

			return MIMEERR::OK;
			}

		string Serialize() const
			{
			string r;
			for (auto&s : strs)
				{
				if (r.length())
					r += "; ";
				r += s;
				}
			return r;
			}


		};

	class HEADER
		{
		string left;
		HDRSTRING right;
		bool http = false;

		public:

			bool IsHTTP() const { return http; }
			const string& LeftC() const { return left; }
			string Left() const  { return left; }
			string Right() const { return right.Serialize(); }
			string Right(const char* sub) const { return right.Sub(sub); }
			HDRSTRING& rights() { return right; }

			vector<string> httpsplit()
				{
				vector<string> hd;
				Split(left.c_str(), ' ', hd);
				return hd;
				}


			void operator =(const char* l)
				{
				right.Parse(l);
				}

			MIMEERR Parse(const char* f,bool CanHTTP = false)
				{
				if (!f)
					return MIMEERR::INVALID;
				const char* a = strchr(f, ':');
				if (!a && !CanHTTP)
					return MIMEERR::INVALID;

				const char* a2 = strchr(f, ' ');
				if ((a2 < a) && CanHTTP)
					a = 0;

				if (!a && CanHTTP)
					{
					left = f;
					http = true;
					return MIMEERR::OK;
					}

				vector<char> d;
				d.resize(a - f + 10);
				strncpy_s(d.data(), d.size(), f, a - f);

				left = d.data();
				a++;
				while (*a == ' ')
					a++;
				right.Parse(a);

				return MIMEERR::OK;
				}

			string Serialize() const
				{
				if (http)
					return left;
				string r;
				r += left;
				r += ": ";
				r += right.Serialize();
				return r;
				}


		};


#define SKIP '\202'
#define NOSKIP 'A'

	const char hexmap[] = {
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		0 ,    1 ,    2 ,    3 ,    4 ,    5 ,    6 ,    7 ,
		8 ,    9 ,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,    10,    11,    12,    13,    14,    15,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,
		SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP,   SKIP
		};

	class CONTENT
		{
		std::vector<HEADER> headers;
		vector<char> data;

		private:


			char* QPDecode(char *input)
				{
				char *s = input;
				char *finalresult = (char*)calloc(strlen(input) + sizeof(char), sizeof(char));
				char *result = finalresult;
				while (*s != '\0') //loop through the entire string...
					{
					if (*s == '=') //woops, needs to be decoded...
						{
						for (int i = 0; i < 3; i++) //is s more than 3 chars long...
							{
							if (s[i] == '\0')
								{
								//error in the decoding...
								return finalresult;
								}
							}
						char mid[3];
						s++; //move past the "="
							 //let's put the hex part into mid...
						bool ok = true;
						for (int i = 0; i < 2; i++)
							{
							if (hexmap[s[i]] == SKIP)
								{
								//we have an error, or a linebreak, in the encoding...
								ok = false;
								if (s[i] == '\r' && s[i + 1] == '\n')
									{
									s += 2;
									//*(result++) = '\r';
									//*(result++) = '\n';
									break;
									}
								else
									{
									//we have an error in the encoding...
									//s--;
									}
								}
							mid[i] = s[i];
							}
						//now we just have to convert the hex string to an char...
						if (ok)
							{
							s += 2;
							int m = hexmap[mid[0]];
							m <<= 4;
							m |= hexmap[mid[1]];
							*(result++) = (char)m;
							}
						}
					else
						{
						if (*s != '\0') *(result++) = *(s++);
						}
					}

				return finalresult;
				}


		public:

			void clear()
				{
				headers.clear();
				data.clear();
				}

			vector<char> GetData() const
				{
				return data;
				}

			vector<HEADER>& GetHeaders() 
			{
				return headers;
			}

			void SetData(vector<char>& x)
				{
				data = x;
				}

			void SetData(const char* a,size_t ss = -1)
				{
				if (ss == -1)
					ss = strlen(a);
				else
					{
					vector<char> d(ss);
					memcpy(d.data(), a, ss);
					SetData(d);
					return;
					}

				string j = a;
				Trim(j);
				if (j.empty())
					return;

				data.resize(j.length());
				memcpy(data.data(), j.c_str(), j.length());
				}

			void DecodeData(vector<char>& d)
				{
				auto a2 = hval("Content-Transfer-Encoding");
				if (_stricmp(a2.c_str(), "base64") == 0)
					{
					DWORD dw = 0;
					CryptStringToBinaryA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64, 0, &dw, 0, 0);
					d.resize(dw);
					CryptStringToBinaryA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64, (BYTE*)d.data(), &dw, 0, 0);
					return;
					}
				if (_stricmp(a2.c_str(), "quoted-printable") == 0)
					{
					vector<char> nd(data.size() + 10);
					strcpy_s(nd.data(), nd.size(), data.data());
					char* ce = QPDecode(nd.data());
					d.resize(strlen(ce) + 1);
					strcpy_s(d.data(), d.size(),ce);
					free(ce);
					return;
					}
				d = data;
				}

			MIME2::HEADER httphdr() const
				{
				for (auto& a : headers)
					{
					if (a.IsHTTP())
						return a;
					}
				MIME2::HEADER me;
				return me;
				}

/*			string Content()  const
				{
				string a;
				auto d2 = data;
				d2.resize(d2.size() + 1);
				a = d2.data();
				d2.resize(d2.size() - 1);
				return a;
				} 
*/

			string hval(const char* left) const
				{
				for (auto& a : headers)
					{
					if (_strcmpi(a.Left().c_str(),left) == 0)
						return a.Right();
					}
				return "";
				}
			string hval(const char* left,const char* rpart) const
				{
				for (auto& a : headers)
					{
					if (_strcmpi(a.Left().c_str(), left) == 0)
						return a.Right(rpart);
					}
				return "";
				}

			HEADER& AddHTTPHeader(const char* l)
				{
				HEADER h;
				h.Parse(l, true);
				headers.insert(headers.begin(), h);
				return headers[0];
				}

			HEADER& operator [](const char* l)
				{
				for (auto& h : headers)
					{
					if (_stricmp(h.Left().c_str(), l) == 0)
						return h;
					}
				HEADER h;
				string e = l;
				e += ": ";
				h.Parse(e.c_str());
				headers.push_back(h);
				return headers[headers.size() - 1];
				}

			MIMEERR Parse(const char* f,bool CanHTTP = false,size_t ss = -1)
				{
				if (!f)
					return MIMEERR::INVALID;

	

				// Until \r\n\r\n
				const char* a2 = strstr(f, "\r\n\r\n");
				int jd = 4;
				const char* a21 = strstr(f, "\n\n");
				if (!a2 && !a21)
					{
					// No headers....
					SetData(f);
					return MIMEERR::OK;
					}
				if (a21 && !a2)
					{
					a2 = a21;
					jd = 2;
					}
				else
				if (!a21 && a2)
					{
					jd = 4;
					}
				else
				if (a21 < a2)
					{
					a2 = a21;
					jd = 2;
					}

				vector<char> hdrs;
				hdrs.resize(a2 - f + 10);
				strncpy_s(hdrs.data(),hdrs.size(), f, a2 - f);

				// Parse them
				vector<string> hd;
				Split(hdrs.data(), '\n', hd);
				for (auto& a : hd)
					{
					HEADER h;
					if ((a[0] == ' ' || a[0] == '\t') && headers.size())
						{
						// Join with previous
						auto& ph = headers[headers.size() - 1];
						ph.rights().getstrings().push_back(Trim(a));
						continue;
						}
					Trim(a);
					auto err = h.Parse(a.c_str(),CanHTTP);
					if (err != MIMEERR::OK)
						return err;
					headers.push_back(h);
					}

				if (ss == -1)
					SetData(a2 + jd);
				else
					SetData(a2 + jd,ss - (a2 - f) - jd);
				return MIMEERR::OK;
				}


/*			string Serialize() const
				{
				string r = SerializeHeaders();
				if (r.length())
					r += "\r\n";
				r += Content();
				return r;
				}
*/
			vector<char> SerializeToVector() const
				{
				string r = SerializeHeaders();
				if (r.length())
					r += "\r\n";
				vector<char> x;
				x.resize(r.length());
				memcpy(x.data(), r.c_str(), r.length());
				auto os = x.size();
				x.resize(x.size() + data.size());
				memcpy(x.data() + os, data.data(),data.size());
				return x;
				}

			string SerializeHeaders() const
				{
				string r;
				for (auto& h : headers)
					{
					r += h.Serialize();
					r += "\r\n";
					}
				return r;
				}




			// Encryption/Decryption
#ifdef MIME_ADES
			inline MIMEERR Encrypt(CONTENT& c, std::vector<PCCERT_CONTEXT> certs, bool BinaryOutput = false,char* useraw = 0,size_t useraws = 0)
			{
				auto C = SerializeToVector();
				if (useraw && useraws)
				{
					C.resize(useraws);
					memcpy(C.data(), useraw, useraws);
				}

				// Add the item
				CRYPT_ENCRYPT_MESSAGE_PARA pa = { 0 };
				pa.cbSize = sizeof(pa);
				pa.dwMsgEncodingType = PKCS_7_ASN_ENCODING;
				pa.ContentEncryptionAlgorithm.pszObjId = szOID_NIST_AES256_CBC;
				DWORD e = 0;
				BOOL A = 0;
				A = CryptEncryptMessage(&pa, (DWORD)certs.size(), certs.data(), (const BYTE*)C.data(), (DWORD)C.size(), 0, &e);
				if (!A)
					return MIMEERR::NOTSIGNED;

				vector<char> zd(e);
				A = CryptEncryptMessage(&pa, (DWORD)certs.size(), certs.data(), (const BYTE*)C.data(), (DWORD)C.size(), (BYTE*)zd.data(), &e);

				if (!A)
					return MIMEERR::NOTSIGNED;
				c["Content-Type"] = "application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"";
				if (BinaryOutput)
				{
					c["Content-Transfer-Encoding"] = "binary";
					char a[100] = { 0 };
					sprintf_s(a, 100, "%llu", (unsigned long long)zd.size());
					c["Content-Length"] = a;
				}
				else
					c["Content-Transfer-Encoding"] = "base64";
				c["Content-Disposition"] = "attachment; filename=\"smime.p7m\"";

				if (BinaryOutput)
					c.SetData(zd);
				else
				{
					string r = Char2Base64(zd.data(), zd.size());
					c.SetData(r.c_str());
				}

				return MIMEERR::OK;
			}

			inline MIMEERR Decrypt(CONTENT& c,vector<char>* pRaw = 0)
			{
				auto a2 = hval("Content-Type");
				auto a3 = hval("Content-Transfer-Encoding");
				if (_strnicmp(a2.c_str(), "application/pkcs7-mime", 22) != 0 && _strnicmp(a2.c_str(), "application/x-pkcs7-mime", 24) != 0)
					return MIMEERR::NOTSIGNED;
				a2 = hval("Content-Type", "smime-type");
				if (strcmp(a2.c_str(), "enveloped-data") != 0)
					return MIMEERR::NOTSIGNED;

				auto hStore = CertOpenStore(
					CERT_STORE_PROV_SYSTEM_W,
					X509_ASN_ENCODING,
					NULL,
					CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
					L"MY");
				if (!hStore)
					return MIMEERR::INVALID;

				CRYPT_DECRYPT_MESSAGE_PARA pa = { 0 };
				pa.cbSize = sizeof(pa);
				pa.rghCertStore = &hStore;
				pa.cCertStore = 1;
				pa.dwMsgAndCertEncodingType = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);
				DWORD u = 0;

				vector<char> data2;
				if (a3 == "base64")
					Base64ToChar(data.data(), data.size(), data2);
				else
				if (a3 == "binary")
					data2 = data;
				else
					return MIMEERR::INVALID;
				int Z = CryptDecryptMessage(&pa, (BYTE*)data2.data(), (DWORD)data2.size(), 0, &u, 0);
				vector<char> res(u);
				Z = CryptDecryptMessage(&pa, (BYTE*)data2.data(), (DWORD)data2.size(), (PBYTE)res.data(), &u, 0);
				CertCloseStore(hStore, 0);
				if (Z != 1)
					return MIMEERR::ERRSIGN;
				res.resize(res.size() + 1);
				if (pRaw)
					*pRaw = res;
				c.Parse(res.data());
				return MIMEERR::OK;
			}

			// Signing using AdES Library...
			MIMEERR Sign(CONTENT& co,AdES::LEVEL lev, vector<AdES::CERT> certs2, AdES::SIGNPARAMETERS* sp = 0, bool BinaryOutput = false)
			{
				MIMEERR err = MIMEERR::NOTSIGNED;
				/*vector<AdES::CERT> certs2;
				for (auto& c : certs)
				{
					AdES::CERT ce;
					ce.cert.cert = c;
					certs2.push_back(ce);
				}*/
				auto C = SerializeToVector();
				vector<char> Signature;
				AdES a;
				AdES::SIGNPARAMETERS Pars;
				if (sp)
					Pars = *sp;
				
				auto hr = a.Sign(lev,C.data(), (DWORD)C.size(), certs2, Pars, Signature);
				if (FAILED(hr))
					return err;

				if (Pars.Attached == AdES::ATTACHTYPE::ATTACHED)
				{
					co.headers.clear();
					co["Content-Type"] = "application/pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"";
					if (BinaryOutput)
					{
						co["Content-Transfer-Encoding"] = "binary";
						char aa[100] = { 0 };
						sprintf_s(aa, 100, "%llu", (unsigned long long)Signature.size());
						co["Content-Length"] = aa;
					}
					else
						co["Content-Transfer-Encoding"] = "base64";
					co["Content-Disposition"] = "attachment; filename=\"smime.p7m\"";

					if (BinaryOutput)
						co.SetData(Signature);
					else
						co.SetData(Char2Base64(Signature.data(), Signature.size()).c_str());

				}
				else
				{
					CONTENT ct;
					ct["Content-Type"] = "application/x-pkcs7-signature; name=\"smime.p7s\"";

					if (BinaryOutput)
					{
						ct["Content-Transfer-Encoding"] = "binary";
						char aa[100] = { 0 };
						sprintf_s(aa, 100, "%llu", (unsigned long long)Signature.size());
						ct["Content-Length"] = aa;
					}
					else
						ct["Content-Transfer-Encoding"] = "base64";

					ct["Content-Disposition"] = "attachment; filename=\"smime.p7s\"";
					if (BinaryOutput)
						ct.SetData(Signature);
					else
						ct.SetData(Char2Base64(Signature.data(), Signature.size()).c_str());
					BuildZ(*this, ct, co, "multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=\"sha256\"");
				}
				return MIMEERR::OK;
			}

			inline MIMEERR Verify(vector<PCCERT_CONTEXT>* Certs = 0, AdES::LEVEL* plev = 0)
			{
				auto axx = hval("Content-Type", "multipart/signed");
				if (axx.length() == 0)
				{
					// Attached
					auto a2 = hval("Content-Type");
					auto a3 = hval("Content-Transfer-Encoding");
					if (_strnicmp(a2.c_str(), "application/pkcs7-mime", 22) != 0)
						return MIMEERR::NOTSIGNED;
					a2 = hval("Content-Type", "smime-type");
					if (strcmp(a2.c_str(), "signed-data") != 0)
						return MIMEERR::NOTSIGNED;

					vector<char> data2;
					if (a3 == "base64")
						Base64ToChar(data.data(), data.size(), data2);
					else
						if (a3 == "binary")
							data2 = data;
						else
							return MIMEERR::INVALID;

					AdES a;
					AdES::LEVEL lev;
					auto hr = a.Verify(data2.data(), (DWORD)data2.size(), lev, 0, 0, 0, Certs, 0);
					if (FAILED(hr))
						return MIMEERR::NOTSIGNED;

					if (plev)
						*plev = lev;
					return MIMEERR::OK;
				}

				auto a3 = hval("Content-Type", "boundary");
				if (!a3.length())
					return MIMEERR::ERRSIGN;

				vector<CONTENT> vv;
				ParseMultipleContent2(data.data(), data.size(), a3.c_str(), vv);
				if (vv.size() != 2)
					return MIMEERR::ERRSIGN;


				vector<char> cert;
				vector<char> Sig;
				if (_stricmp(vv[0].hval("Content-Type", "application/x-pkcs7-signature").c_str(), "application/x-pkcs7-signature") == 0)
				{
					vv[0].DecodeData(cert);
					Sig = vv[1].SerializeToVector();
				}
				if (_stricmp(vv[1].hval("Content-Type", "application/x-pkcs7-signature").c_str(), "application/x-pkcs7-signature") == 0)
				{
					vv[1].DecodeData(cert);
					Sig = vv[0].SerializeToVector();
				}
				if (_stricmp(vv[0].hval("Content-Type", "application/pkcs7-signature").c_str(), "application/pkcs7-signature") == 0)
				{
					vv[0].DecodeData(cert);
					Sig = vv[1].SerializeToVector();
				}
				if (_stricmp(vv[1].hval("Content-Type", "application/pkcs7-signature").c_str(), "application/pkcs7-signature") == 0)
				{
					vv[1].DecodeData(cert);
					Sig = vv[0].SerializeToVector();
				}
				if (cert.empty())
					return MIMEERR::ERRSIGN;

				// Sig = message
				// cert = Signature;
				AdES a;
				AdES::LEVEL lev;
				auto hr = a.Verify(cert.data(), (DWORD)cert.size(), lev,Sig.data(), (DWORD)Sig.size(),0,Certs,0);
				if (FAILED(hr))
					return MIMEERR::NOTSIGNED;
				if (plev)
					*plev = lev;
				return MIMEERR::OK;
			}


			// Whops. Not standard, but I like experimental stuff.
			MIMEERR XMLSign(CONTENT& co, AdES::LEVEL lev, vector<AdES::CERT> certs2, AdES::SIGNPARAMETERS* sp = 0)
			{
				MIMEERR err = MIMEERR::NOTSIGNED;
				/*vector<AdES::CERT> certs2;
				for (auto& c : certs)
				{
					AdES::CERT ce;
					ce.cert.cert = c;
					certs2.push_back(ce);
				}*/
				auto C = SerializeToVector();
				vector<char> Signature;
				AdES a;
				AdES::SIGNPARAMETERS Pars;
				if (sp)
					Pars = *sp;

				if (certs2.size() > 1 && Pars.Attached == AdES::ATTACHTYPE::ENVELOPED)
					Pars.Attached = AdES::ATTACHTYPE::ENVELOPING;
				

				std::vector<AdES::FILEREF> d;
				AdES::FILEREF tu(data.data(),data.size(),"ref1");
				auto hr = a.XMLSign(lev, d, certs2, Pars, Signature);
				if (FAILED(hr))
					return err;

				if (Pars.Attached == AdES::ATTACHTYPE::ATTACHED)
				{
					co.headers.clear();
					co["Content-Type"] = "text/xml; smime-type=signed-data; name=\"smime.xml\"";
					co["Content-Transfer-Encoding"] = "base64";
					co["Content-Disposition"] = "attachment; filename=\"smime.xml\"";

					co.SetData(Char2Base64(Signature.data(), Signature.size()).c_str());
				}
				else
				{
					CONTENT ct;
					ct["Content-Type"] = "text/xml; name=\"smime.xml\"";
					ct["Content-Transfer-Encoding"] = "base64";

					ct["Content-Disposition"] = "attachment; filename=\"smime.xml\"";
					ct.SetData(Char2Base64(Signature.data(), Signature.size()).c_str());
					BuildZ(*this, ct, co, "multipart/signed; protocol=\"text/xml\"; micalg=\"sha256\"");
				}
				return MIMEERR::OK;
			}

	#endif		


		};


	class CONTENTBUILDER
		{
		vector<vector<char>> parts;
		string Boundary;

		public:

			CONTENTBUILDER()
				{
				UUID u = { 0 };
				CoCreateGuid(&u);
				//* test :)
				TCHAR str[1000];
				StringFromGUID2(u, str, 1000);
				char star[1000];
				WideCharToMultiByte(CP_UTF8, 0, str, -1, star, 1000, 0, 0);
				Boundary = star;
				}

			void clear()
				{
				parts.clear();
				}

			void Add(char* Data)
				{
				vector<char> x(strlen(Data));
				memcpy(x.data(), Data, strlen(Data));
				parts.push_back(x);
				}

			void Add(CONTENT& c)
				{
				auto h1 = c.SerializeToVector();
				parts.push_back(h1);
				}

			vector<vector<char>>& GetParts() { return parts; }

			void Build(CONTENT& c,const char* Sign = 0)
				{
				c.clear();
				c["MIME-Version"] = "1.0";
				string a = "multipart/mixed";
				if (Sign)
					a = Sign;
				a += "; boundary=\"";
				a += Boundary;
				a += "\"";
				c["Content-Type"] = a.c_str();

				vector<char> d;
				for (auto& aa : parts)
					{
					string j = "--";
					j += Boundary;
					j += "\r\n";

					vector<char> jj(j.length() + aa.size() + 2);
					memcpy(jj.data(), j.c_str(), j.length());
					memcpy(jj.data() + j.length(), aa.data(), aa.size());
					memcpy(jj.data() + j.length() + aa.size(), "\r\n",2);
					auto es = d.size();
					d.resize(es + jj.size());
					memcpy(d.data() + es, jj.data(), jj.size());
					}

				auto es = d.size();
				d.resize(es + 2 + Boundary.size() + 4);
				memcpy(d.data() + es, "--",2);
				memcpy(d.data() + es + 2, Boundary.c_str(), Boundary.size());
				memcpy(d.data() + es + 2 + Boundary.size(), "--\r\n",4);

				c.SetData(d);
				}
		};

	inline void BuildZ(CONTENT&c1,CONTENT&c2,CONTENT&co,const char* s)
		{
		CONTENTBUILDER cb2;
		cb2.Add(c1);
		cb2.Add(c2);
		cb2.Build(co,s);

		}
	inline MIMEERR ParseMultipleContent2(const char* d, size_t sz, const char* del, vector<CONTENT>& Result)
		{
		if (!d || !del)
			return MIMEERR::INVALID;

		string dx = "--";
		dx += del;
		vector<vector<char>> r;

		BinarySplit(d, sz, dx.c_str(), r);

		if (r.size() < 2)
			return MIMEERR::INVALID;

		string delj = "--";
		delj += del;
		// First, check if [0] starts with it
		if (r[0].size() == 0 || strncmp(r[0].data(), delj.c_str(), delj.length()) != 0)
			r.erase(r.begin());

		// Check last if it starts with --
		if (strncmp(r[r.size() - 1].data(), "--", 2) == 0)
			r.erase(r.end() - 1);
		else
			return MIMEERR::INVALID;


		for (auto& a : r)
			{
			CONTENT c;
			Trim(a,2);
			TrimOnce(a);
			auto ra = a;
			ra.resize(ra.size() + 1);
			auto err = c.Parse(ra.data(),0,ra.size() - 1);
			if (err != MIMEERR::OK)
				return err;

			Result.push_back(c);
			}


		return MIMEERR::OK;
		}



	}

