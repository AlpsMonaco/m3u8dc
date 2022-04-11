#include <assert.h>

#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"

#include <iostream>
#include <streambuf>
#include <string>
#include <vector>
#include <exception>
#include <thread>
#include <atomic>
#include <mutex>

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "httplib.h"

#pragma comment(lib, "capi.lib")
#pragma comment(lib, "dasync.lib")
#pragma comment(lib, "ec_internal_test.lib")
#pragma comment(lib, "legacy.lib")
#pragma comment(lib, "libapps.lib")
#pragma comment(lib, "libcommon.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libcrypto_static.lib")
#pragma comment(lib, "libdefault.lib")
#pragma comment(lib, "liblegacy.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libssl_static.lib")
#pragma comment(lib, "libtestutil.lib")
#pragma comment(lib, "loader_attic.lib")
#pragma comment(lib, "openssl.lib")
#pragma comment(lib, "ossltest.lib")
#pragma comment(lib, "padlock.lib")
#pragma comment(lib, "p_test.lib")

using namespace CryptoPP;

std::ofstream downloadLog("download.log", std::ios_base::trunc);
std::ofstream encryptLog("encrypt.log", std::ios_base::trunc);
std::mutex logLock;

std::string AES128Encrypt(const std::string &plain, const std::string &key, const std::string &iv)
{
	std::string cipher;
	try
	{
		CBC_Mode<AES>::Encryption e;
		e.SetKeyWithIV(reinterpret_cast<const byte *>(key.c_str()), key.size(), reinterpret_cast<const byte *>(iv.c_str()));
		StringSource ss(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
	}
	catch (const Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
	return cipher;
}

std::string AES128Decrypt(const std::string &cipherText, const std::string &key, const std::string &iv)
{
	std::string plain;
	try
	{
		CBC_Mode<AES>::Decryption d;
		d.SetKeyWithIV(reinterpret_cast<const byte *>(key.c_str()), key.size(), reinterpret_cast<const byte *>(iv.c_str()));
		StringSource ss(cipherText, true, new StreamTransformationFilter(d, new StringSink(plain)));
	}
	catch (const Exception &e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
	return plain;
}

std::string GetStream(const std::string &fileName)
{
	static std::ifstream ifs;
	ifs.open(fileName, std::ios_base::binary);
	assert(ifs.is_open());
	std::string result((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
	ifs.close();
	return result;
}

std::string ProcessRaw(const char *raw)
{
	std::string s = raw;
	size_t pos = s.find_first_of("[", 0);
	if (pos != std::string::npos)
		s.erase(pos, 1);
	pos = s.find_last_of("]");
	if (pos != std::string::npos)
		s.erase(pos);
	std::string result;
	size_t begin = 0;
	while ((pos = s.find(", ", begin)) != std::string::npos)
	{
		result.push_back(atoi(s.substr(begin, pos - begin).c_str()));
		begin = pos + 2;
	}
	result.push_back(atoi(s.substr(begin, s.size()).c_str()));
	return result;
}

class OpenFileError : std::exception
{
public:
	OpenFileError() {}
	const char *what() const throw()
	{
		return "open file failed";
	}
};

class EmptyFileException : std::exception
{
public:
	EmptyFileException() {}
	const char *what() const throw()
	{
		return "file is empty";
	}
};

httplib::Headers &GetHeaders()
{
	static httplib::Headers headers{
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "zh-CN,zh;q=0.9"},
		{"Connection", "keep-alive"},
		{"Host", "uc-dts.videocc.net"},
		{"sec-ch-ua", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"100\", \"Google Chrome\";v=\"100\""},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", "\"Windows\""},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"},
	};
	return headers;
}

std::string GetFileName(const std::string &url)
{
	size_t beginPos = 0, endPos = 0;
	endPos = url.find(".ts");
	beginPos = url.substr(0, endPos).rfind("_") + 1;
	return url.substr(beginPos, endPos - beginPos);
}

void DownloadClip(const std::string &url)
{
	logLock.lock();
	downloadLog << "downloading \"" << url << "\"" << std::endl;
	std::cout << "downloading \"" << url << "\"" << std::endl;
	logLock.unlock();
	size_t count = 0;
	size_t hostBeginPos = 0;
	std::string host;
	std::string endpoint;
	for (int i = 0; i < url.size(); i++)
	{
		if (url[i] == '/')
			count++;
		if (count == 2)
		{
			hostBeginPos = hostBeginPos == 0 ? i + 1 : hostBeginPos;
		}
		if (count == 3)
		{
			host = url.substr(hostBeginPos, i - hostBeginPos);
			endpoint = url.substr(i, url.size());
			break;
		}
	}
	std::string fileName = GetFileName(url);
	httplib::SSLClient c(host);
	c.set_read_timeout(30);
	auto result = c.Get(endpoint.c_str(), GetHeaders());
	if (result.error() != httplib::Error::Success)
	{
		logLock.lock();
		downloadLog << "download error:" << httplib::to_string(result.error()) << url << std::endl;
		std::cout << "download error:" << httplib::to_string(result.error()) << url << std::endl;
		logLock.unlock();
	}
	else
	{
		std::ofstream ofs(fileName + ".ts", std::ios_base::binary | std::ios_base::trunc);
		ofs << result.value().body;
		ofs.close();
		logLock.lock();
		downloadLog << "download \"" << url << "\" finish" << std::endl;
		std::cout << "download \"" << url << "\" finish" << std::endl;
		logLock.unlock();
	}
}

std::vector<std::string> GetVideoClipsUrl()
{
	std::ifstream ifs("url.txt");
	if (!ifs.is_open())
	{
		throw OpenFileError();
	}
	std::string fileContent((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
	static const char *crlf = "\r\n";
	static const char *lf = "\n";
	const char *delimeter;
	std::vector<std::string> result;
	if (fileContent.find(crlf, 0) != std::string::npos)
		delimeter = crlf;
	else
		delimeter = lf;
	size_t delimeterSize = strlen(delimeter);
	size_t begin = 0;
	size_t pos = 0;
	while ((pos = fileContent.find(delimeter, begin)) != std::string::npos)
	{
		const std::string &line = fileContent.substr(begin, pos - begin);
		if (line[0] != '#')
		{
			if (line != "")
				result.emplace_back(std::move(line));
		}
		begin = pos + delimeterSize;
	}
	if (begin < fileContent.size())
	{
		const std::string &line = fileContent.substr(begin, fileContent.size());
		if (line[0] != '#')
		{
			if (line != "")
				result.emplace_back(std::move(line));
		}
	}
	return result;
}

std::string GetKey(const char *rawKey) { return ProcessRaw(rawKey); }
std::string GetIV(const char *rawIV) { return ProcessRaw(rawIV); }

const char *GetRawKey()
{
	static std::string rawKey;
	constexpr char *fileName = "key.txt";
	std::ifstream ifs(fileName, std::ios_base::binary);
	if (!ifs.is_open())
		throw OpenFileError();
	rawKey.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
	return rawKey.c_str();
}

const char *GetRawIV()
{
	static std::string rawIV;
	constexpr char *fileName = "iv.txt";
	std::ifstream ifs(fileName, std::ios_base::binary);
	if (!ifs.is_open())
		throw OpenFileError();
	rawIV.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
	return rawIV.c_str();
}

void MergeClips(int end, const std::string &key, const std::string &iv)
{
	std::ofstream ofs("result.ts", std::ios_base::binary | std::ios_base::trunc);
	if (!ofs.is_open())
		throw OpenFileError();
	std::ifstream ifs;
	std::string buffer;
	for (int i = 0; i <= end; i++)
	{
		ifs.open(std::to_string(i) + ".ts", std::ios_base::binary);
		if (!ifs.is_open())
			throw OpenFileError();
		buffer.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
		if (buffer.size() == 0)
			throw EmptyFileException();
		ofs << AES128Decrypt(buffer, key, iv);
		ifs.close();
	}
	ofs.close();
}

// const char *rawKey = "[60, 248, 222, 224, 65, 78, 173, 48, 169, 249, 146, 188, 115, 54, 56, 36];";
// const char *rawIV = "[19, 83, 149, 72, 66, 0, 200, 211, 81, 168, 61, 102, 72, 6, 44, 188]";

int main(int argc, char *argv[])
{
#ifndef DECRYPTOR
	std::atomic<size_t> count(0);
	std::vector<std::string> list = GetVideoClipsUrl();
	size_t end = list.size();
	constexpr int threadNum = 5;
	std::thread threadList[threadNum];
	for (int i = 0; i < threadNum; i++)
	{
		threadList[i] = std::thread([&](int threadNo) -> void
									{
										logLock.lock();
										std::cout << "thread(" << threadNo << ") begin"<< std::endl;
										logLock.unlock();
										size_t num;
										for(;;){
										num = count++;
										if(num >=end)
										{
											logLock.lock();
											std::cout << "thread(" << threadNo << ") exit"<< std::endl;
											logLock.unlock();
											return;
										};
										DownloadClip(list[num]);} },
									i);
	}
	for (int i = 0; i < threadNum; i++)
	{
		threadList[i].join();
	}
#else
	if (argc == 1)
	{
		std::cerr << "need end range" << std::endl;
		return 1;
	}
	std::string key = GetKey(GetRawKey());
	std::string iv = GetIV(GetRawIV());
	MergeClips(atoi(argv[1]), key, iv);
#endif
	return 0;
}