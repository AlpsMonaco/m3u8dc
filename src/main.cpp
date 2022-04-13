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
#include <shared_mutex>

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

std::ofstream &GetDownloadLog()
{
	static std::ofstream downloadLog("download.log", std::ios_base::trunc);
	return downloadLog;
}

std::ofstream &GetDecryptLog()
{
	static std::ofstream decryptLog("decrypt.log", std::ios_base::trunc);
	return decryptLog;
}

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
		std::ofstream &decryptLog = GetDecryptLog();
		decryptLog << "decrypt video error:" << e.what() << std::endl;
		std::cerr << "decrypt video error:" << e.what() << std::endl;
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

class OpenFileError : public std::exception
{
public:
	OpenFileError(const char *fileName)
	{
		info = "Open file error: ";
		info += fileName;
	}
	const char *what() const throw() { return info.c_str(); }

protected:
	static std::string info;
};

std::string OpenFileError::info = "";

class EmptyFileException : public std::exception
{
public:
	EmptyFileException() {}
	const char *what() const throw() { return "file is empty"; }
};

class KeyNotFoundException : public std::exception
{
public:
	KeyNotFoundException(const char *key)
	{
		this->info = key;
		this->info += " not found";
	}
	const char *what() const throw() { return this->info.c_str(); }

protected:
	static std::string info;
};
std::string KeyNotFoundException::info = "";

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

bool DownloadClip(const std::string &url)
{
	std::ofstream &downloadLog = GetDownloadLog();
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
	constexpr int maxTryCount = 10;
	int tryCount = 0;
	for (;;)
	{
		tryCount++;
		httplib::SSLClient c(host);
		c.set_read_timeout(30);
		auto result = c.Get(endpoint.c_str(), GetHeaders());
		if (result.error() != httplib::Error::Success)
		{
			if (tryCount <= maxTryCount)
				continue;
			else
				return false;
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
			downloadLog << "download success:\"" << url << std::endl;
			std::cout << "download success:\"" << url << std::endl;
			logLock.unlock();
			return true;
		}
	}
}

std::vector<std::string> GetVideoClipsUrl(const char *filePath)
{
	std::ifstream ifs(filePath);
	if (!ifs.is_open())
	{
		throw OpenFileError(filePath);
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
		throw OpenFileError(fileName);
	rawKey.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
	return rawKey.c_str();
}

const char *GetRawIV()
{
	static std::string rawIV;
	constexpr char *fileName = "iv.txt";
	std::ifstream ifs(fileName, std::ios_base::binary);
	if (!ifs.is_open())
		throw OpenFileError(fileName);
	rawIV.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
	return rawIV.c_str();
}

void MergeClips(int end, const std::string &key, const std::string &iv)
{
	std::ofstream &decryptLog = GetDecryptLog();
	static constexpr char *resultFileName = "result.m3u8";
	std::ofstream ofs(resultFileName, std::ios_base::binary | std::ios_base::trunc);
	if (!ofs.is_open())
		throw OpenFileError(resultFileName);
	decryptLog << "begin decrypt..." << std::endl;
	std::ifstream ifs;
	std::string buffer;
	for (int i = 0; i <= end; i++)
	{
		const std::string &tempFileName = std::to_string(i) + ".ts";
		ifs.open(tempFileName, std::ios_base::binary);
		if (!ifs.is_open())
			throw OpenFileError(tempFileName.c_str());
		buffer.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
		if (buffer.size() == 0)
			throw EmptyFileException();
		ofs << AES128Decrypt(buffer, key, iv);
		ifs.close();
	}
	ofs.close();
	decryptLog << "decrypt success" << std::endl;
}

/**
 * @brief m3u8dc.exe <m3u8_file> <key_with_iv.json>
 * @param m3u8_file m3u8 standard format
 * @param key_with_iv_file {"key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], "iv":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
 */

#ifndef _SPLIT_FEATURES_

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

class HistoryMgr
{
public:
	/**
	 * history.json {"history":[0,1,2,3]}
	 */
	HistoryMgr()
	{
		std::ifstream ifs("history.json", std::ios_base::binary);
		if (ifs.is_open())
		{
			std::string historyContent((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
			d.Parse(historyContent.c_str());
			ifs.close();
			if (d.HasParseError())
			{
				std::cerr << "parse history.json error" << std::endl;
				return;
			}
			if (!d.HasMember("history"))
			{
				std::cerr << "history.json has no history" << std::endl;
				return;
			}
			const rapidjson::Value &history = d["history"];
			if (!history.IsArray())
			{
				std::cerr << "history.json history is not array" << std::endl;
				return;
			}
			for (rapidjson::SizeType i = 0; i < history.Size(); i++)
			{
				if (!history[i].IsInt())
				{
					std::cerr << "a value is not int" << std::endl;
					continue;
				}
				historySet.emplace(history[i].GetInt());
			}
		}
	}

	bool IsExist(int index)
	{
		this->mu.lock_shared();
		bool result = historySet.find(index) != historySet.end();
		this->mu.unlock_shared();
		return result;
	}

	void Add(int index)
	{
		this->mu.lock();
		historySet.emplace(index);
		this->mu.unlock();
	}

	void Save()
	{
		this->mu.lock();
		d.SetObject();
		rapidjson::Value history(rapidjson::kArrayType);
		for (const auto &i : historySet)
		{
			rapidjson::Value v(i);
			history.PushBack(v, d.GetAllocator());
		}
		d.AddMember("history", history, d.GetAllocator());
		std::ofstream ofs("history.json", std::ios_base::binary | std::ios_base::trunc);
		if (!ofs.is_open())
		{
			std::cerr << "open history.json error" << std::endl;
			this->mu.unlock();
			return;
		}
		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		d.Accept(writer);
		ofs << buffer.GetString();
		ofs.close();
		this->mu.unlock();
	}

protected:
	std::shared_mutex mu;
	std::set<long long> historySet;
	rapidjson::Document d;
};

void PrintHelp()
{
	std::cout << R"( usage m3u8dc.exe <m3u8_file> <key_with_iv.json>

 m3u8_file a m3u8 file with standard m3u8 format

 key_with_iv_file a json file contains {"key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], "iv":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]})"
			  << std::endl;
}

void Download(const std::vector<std::string> &list, HistoryMgr &historyMgr)
{
	std::atomic<size_t> count(0);
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
										if(historyMgr.IsExist(num))
										{
											logLock.lock();
											std::cout << "clip " << num << " downloaded,skip..." << std::endl;
											GetDownloadLog() << "clip " << num << " downloaded,skip..." << std::endl;
											logLock.unlock();
											continue;
										}
										DownloadClip(list[num]);
										historyMgr.Add(num);
										} },
									i);
	}
	for (int i = 0; i < threadNum; i++)
		threadList[i].join();
}

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		PrintHelp();
		return 1;
	}
	try
	{
		HistoryMgr historyMgr;
		std::vector<std::string> list;
		list = GetVideoClipsUrl(argv[1]);
		Download(list, historyMgr);

		rapidjson::Document d;
		std::ifstream ifs(argv[2], std::ios_base::binary);
		if (!ifs.is_open())
			throw OpenFileError(argv[2]);

		std::string keyWithIv((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
		ifs.close();
		if (keyWithIv.size() == 0)
			throw EmptyFileException();
		d.Parse(keyWithIv.c_str());
		if (d.HasParseError())
		{
			std::cerr << std::string("parse json file") + argv[2] + "failed" << std::endl;
			return 1;
		}
		if (!d.HasMember("key") || !d["key"].IsArray() || !d.HasMember("iv") || !d["iv"].IsArray())
		{
			std::cerr << "key or iv is not array" << std::endl;
			return 1;
		}
		const rapidjson::Value &keyArray = d["key"];
		std::string key(keyArray.Size(), '\0');
		for (int i = 0; i < keyArray.Size(); i++)
			key[i] = keyArray[i].GetInt();
		const rapidjson::Value &ivArray = d["iv"];
		std::string iv(ivArray.Size(), '\0');
		for (int i = 0; i < ivArray.Size(); i++)
			iv[i] = ivArray[i].GetInt();
		MergeClips(list.size() - 1, key, iv);
		historyMgr.Save();
		return 0;
	}
	catch (std::exception &e)
	{
		std::cerr << e.what() << std::endl;
		return -1;
	}
	return 0;
}

#else

int main(int argc, char *argv[])
{
	try
	{
#ifndef DECRYPTOR
		if (argc == 1)
		{
			std::cerr << "need m3u8 file";
			return 1;
		}
		std::atomic<size_t> count(0);
		std::vector<std::string> list;
		list = GetVideoClipsUrl(argv[1]);
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
	}
	catch (std::exception &e)
	{
		std::cerr << e.what() << std::endl;
		return 1;
	}
	return 0;
}

#endif