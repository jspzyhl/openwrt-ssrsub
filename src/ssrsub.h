#pragma once

#include <string>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <locale>
#include <assert.h>
#include <vector>
#include <utility>

#include "cppcodec/base64_url_unpadded.hpp"

#include <stdio.h>
#ifdef _MSC_VER
#define POPEN(cmd,mode) _popen(cmd,mode)
#define PCLOSE(f) _pclose(f)
#else
#define POPEN(cmd,mode) popen(cmd,mode)
#define PCLOSE(f) pclose(f)
#endif

#ifdef _MSC_VER
#include <io.h>
#define ACCESS(_filepath,mode) _access(_filepath,mode)
#else
#include <unistd.h>
#define ACCESS(_filepath,mode) access(_filepath,mode)
#endif

using b64 = cppcodec::base64_url_unpadded;
class FSSRConfig;

namespace ssrsub
{
std::string ExecShell(const char* cmd)
{
	char buffer[128];
	std::string result = "";
	FILE* pipe = POPEN(cmd, "r");
	if (!pipe)
		throw std::runtime_error("popen() failed!");
	try
	{
		while (fgets(buffer, sizeof buffer, pipe) != NULL)
		{
			result += buffer;
		}
	} catch (...)
	{
		PCLOSE(pipe);
		throw;
	}
	PCLOSE(pipe);
	return result;
}

bool IsIPAddrCheck(const std::string& Inval)
{
	std::stringstream ss(Inval);
	std::string l;
	unsigned char count = 0;
	while (std::getline(ss, l, '.'))
	{
		count += 1;
		if (count > 4)
		{
			return false;
		}

		char* p = nullptr;
		unsigned long number = strtoul(l.c_str(), &p, 10);
		if (*p)
		{
			return false;
		}
		if (number > 255)
		{
			return false;
		}
	}
	return true;
}

std::string ResolveToIP(const std::string& Inval, const std::string& dns)
{
	if (IsIPAddrCheck(Inval))
	{
		return Inval;
	}
	std::string digcmd("dig +short ");
	digcmd.push_back('@');
	digcmd.append(dns);
	digcmd.push_back(' ');
	digcmd.append(Inval);
	std::string digresult = ExecShell(digcmd.c_str());
	std::stringstream sdigresult(digresult);
	std::string l;
	while (std::getline(sdigresult, l, '\n'))
	{
		if (IsIPAddrCheck(l))
		{
			return l;
		}
	}
	return std::string();
}

void DecB64(const std::string& Inval, std::string& OutVal)
{
	std::string workingstr(Inval);
	std::remove_if(workingstr.begin(), workingstr.end(), isspace);

	std::vector<uint8_t> decdat = b64::decode(workingstr);
	OutVal.clear();
	for (auto it = decdat.begin(); it != decdat.end(); ++it)
	{
		OutVal.push_back(*it);
	}
}

}

using namespace ssrsub;

class FSSRConfig
{

public:

	std::string server;
	std::string port;
	std::string protocol;
	std::string method;
	std::string obfs;
	std::string password;
	std::string obfsparam;
	std::string protoparam;
	std::string remarks;
	std::string group;

	void Parse(const std::string& ssrURL, const std::string& dns)
	{
		std::size_t ssrurlLen = ssrURL.length();
		const std::size_t ssrheaderLen = 6;
		std::size_t headerpos = ssrURL.find("ssr://");
		if (std::string::npos == headerpos)
		{
			return;
		}
		std::string ssrb64 = ssrURL.substr(headerpos + ssrheaderLen,
				ssrurlLen - headerpos - ssrheaderLen);
		std::string ssrParams;
		DecB64(ssrb64, ssrParams);

		const std::size_t spLen = 2;
		std::size_t spliterpos = ssrParams.find("/?");
		std::string serverparams(ssrParams.substr(0, spliterpos));
		std::string paramsb64(
				ssrParams.substr(spliterpos + spLen,
						ssrParams.length() - spliterpos - spLen));

		std::stringstream ss_serverparams(serverparams);
		std::string l;
		unsigned char count = 0;

		while (std::getline(ss_serverparams, l, ':'))
		{
			switch (count)
			{
			case (0):
			{
				server = ResolveToIP(l, dns);
				break;
			}
			case (1):
			{
				port = l;
				break;
			}
			case (2):
			{
				protocol = l;
				break;
			}
			case (3):
			{
				method = l;
				break;
			}
			case (4):
			{
				obfs = l;
				break;
			}
			case (5):
			{
				DecB64(l, password);
				break;
			}

			}
			count += 1;
		}

		PickSegmentValue(paramsb64, "obfsparam", obfsparam);
		DecB64(obfsparam, obfsparam);
		PickSegmentValue(paramsb64, "protoparam", protoparam);
		DecB64(protoparam, protoparam);
		PickSegmentValue(paramsb64, "remarks", remarks);
		DecB64(remarks, remarks);
		PickSegmentValue(paramsb64, "group", group);
		DecB64(group, group);
	}

	//	Alias: "[group] remarks"
	void GetAlias(std::string& OutAlias)
	{
		OutAlias.clear();
		OutAlias.push_back('[');
		OutAlias.append(group);
		OutAlias.append("] ");
		OutAlias.append(remarks);
	}

	static void SplitAlias(const char* strAlias, std::string& outgroup,
			std::string& outremarks)
	{
		const char* pL = strchr(strAlias, '[');
		const char* pR = strchr(strAlias, ']');
		if (pR >= pL)
		{
			size_t gpLen(pR - pL - 1);
			std::string gp(pL + 1, gpLen);
			outgroup.clear();
			outgroup = std::move(gp);
			size_t headerLen(pR + 2 - strAlias);
			size_t rmkLen( strlen(strAlias)-headerLen);
			std::string rmk(pR + 2, rmkLen);
			outremarks.clear();
			outremarks = std::move(rmk);
		}
	}

private:

	void PickSegmentValue(const std::string& Inval,
			const std::string& SegmentName, std::string& ValueOutput)
	{
		std::string SearchStr(SegmentName);
		SearchStr.push_back('=');
		std::size_t segpos = Inval.find(SearchStr);
		if (segpos != std::string::npos)
		{
			std::size_t aftersegpos = segpos + SearchStr.length();
			std::size_t nearandpos = Inval.find("&", aftersegpos);
			ValueOutput = Inval.substr(aftersegpos, nearandpos - aftersegpos);
		}
	}

};

class FSSRFileParser
{
public:

	static void DecodeSSRFile(const std::string& FilePath,
			const std::string& dns, std::vector<FSSRConfig>& SSRCfgArray)
	{
		std::ifstream infile;
		infile.open(FilePath.c_str());
		assert(infile.is_open());
		std::string buf;
		buf.clear();
		char c;
		while (true)
		{
			infile.get(c);
			if (infile.eof())
			{
				break;
			}
			if (std::isspace(c) == false)
			{
				buf.push_back(c);
			}
		}
		infile.close();

		std::string decodedbuf;
		DecB64(buf, decodedbuf);
		std::vector<std::string> ssrUrlList;
		SplitLinesToList(decodedbuf, ssrUrlList);

		SSRCfgArray.clear();
		for (auto IT = ssrUrlList.begin(); IT != ssrUrlList.end(); ++IT)
		{
			FSSRConfig newcfg;
			newcfg.Parse(*IT, dns);
			SSRCfgArray.emplace_back(std::move(newcfg));
		}
	}

private:

	static void SplitLinesToList(const std::string& InStr,
			std::vector<std::string>& StrList)
	{
		int islastSpace = 1;
		int iscurrSpace;
		size_t s_pos = 0;
		//	前空白，当前非空白 => 新起点设为当前
		//	前非空白，当前空白 => 终点设为当前-1，并截取字符串
		for (size_t i = 0, n = InStr.length(); i < n; ++i)
		{
			iscurrSpace = std::isspace(InStr[i]);
			if (islastSpace && (!iscurrSpace))
			{
				s_pos = i;
			}
			if ((!islastSpace) && iscurrSpace)
			{
				StrList.push_back(InStr.substr(s_pos, i - s_pos));
			}

			islastSpace = iscurrSpace;
		}
	}

};
