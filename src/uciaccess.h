/*
 * uciaccess.h
 *
 *  Created on: 2019-5-7
 *      Author: jspzyhl
 */

#ifndef UCIACCESS_H_
#define UCIACCESS_H_

#include <memory.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <cstdio>
#include <functional>
#include <utility>
#include <map>
#include <uci.h>
#include "ssrsub.h"

//	return true will continue iterate,otherwise break iterate.
using FUCISectionOperator = std::function<bool (uci_section*)>;

std::hash<std::string> StrHasher;

template<typename uciElementType>
uci_type get_element_uci_type(uciElementType* tp = nullptr)
{
	return uci_type::UCI_TYPE_UNSPEC;
}

template<>
uci_type get_element_uci_type(uci_package* tp)
{
	return uci_type::UCI_TYPE_PACKAGE;
}
template<>
uci_type get_element_uci_type(uci_section* tp)
{
	return uci_type::UCI_TYPE_SECTION;
}
template<>
uci_type get_element_uci_type(uci_option* tp)
{
	return uci_type::UCI_TYPE_OPTION;
}
template<>
uci_type get_element_uci_type(uci_delta* tp)
{
	return uci_type::UCI_TYPE_DELTA;
}
template<>
uci_type get_element_uci_type(uci_backend* tp)
{
	return uci_type::UCI_TYPE_BACKEND;
}

class FuciAccesser
{
public:
	FuciAccesser()
	{

	}
	~FuciAccesser()
	{
		uci_free_context(ctx); //释放上下文
	}

	static uci_element* uci_lookup_list(struct uci_list *list, const char *name)
	{
		uci_element *e;
		uci_foreach_element(list, e)
		{
			if (!strcmp(e->name, name))
				return e;
		}
		return NULL;
	}

	static inline uci_option* GetNamedOption(uci_section* InSection,
			const char* optName)
	{
		return uci_to_option(uci_lookup_list(&InSection->options, optName));
	}

protected:

	/* initialize a list head/item */
	static inline void uci_list_init(struct uci_list *ptr)
	{
		ptr->prev = ptr;
		ptr->next = ptr;
	}

	/* inserts a new list entry after a given entry */
	static inline void uci_list_insert(struct uci_list *list,
			struct uci_list *ptr)
	{
		list->next->prev = ptr;
		ptr->prev = list;
		ptr->next = list->next;
		list->next = ptr;
	}

	/* inserts a new list entry at the tail of the list */
	static inline void uci_list_add(struct uci_list *head, struct uci_list *ptr)
	{
		/* NB: head->prev points at the tail */
		uci_list_insert(head->prev, ptr);
	}

	uci_element* create_uci_element(uci_type type, const char *name, int size)
	{
		uci_element* e;
		void* ptr = malloc(size);
		memset(ptr, 0, size);

		e = (uci_element*) ptr;
		e->type = type;
		if (name)
		{
			e->name = strdup(name);
		}
		uci_list_init(&e->list);
		return e;
	}

	template<typename uciType>
	inline uciType* new_uci_element(const char *name, int payloadSize)
	{
		uci_element* ptr = create_uci_element(get_element_uci_type<uciType>(),
				name, sizeof(uciType) + payloadSize);
		return container_of(ptr, uciType, e);
	}

	uci_option* uci_alloc_option(struct uci_section *s, const char *name,
			const char *value)
	{
		uci_option *o;
		o = new_uci_element<uci_option>(name, strlen(value) + 1);
		o->type = uci_option_type::UCI_TYPE_STRING;
		o->v.string = uci_dataptr(o);
		o->section = s;
		strcpy(o->v.string, value);
		uci_list_add(&s->options, &o->e.list);
		return o;
	}

	uci_delta* uci_add_delta(uci_list* deltalist, uci_command cmd,
			const char *section, const char *option, const char *value)
	{
		uci_delta *h = nullptr;
		int size = strlen(section) + 1;
		char* ptr;

		if (value)
			size += strlen(value) + 1;

		h = new_uci_element<uci_delta>(option, size);
		ptr = uci_dataptr(h);
		h->cmd = cmd;
		h->section = strcpy(ptr, section);
		if (value)
		{
			ptr += strlen(ptr) + 1;
			h->value = strcpy(ptr, value);
		}
		uci_list_add(deltalist, &h->e.list);
		return h;
	}

protected:

	uci_context * ctx = uci_alloc_context(); //申请上下文
};

class FSSRCFGAccesser: protected FuciAccesser
{
public:

	FSSRCFGAccesser()
	{
		RenewSSRContext("shadowsocksr");
	}

	~FSSRCFGAccesser()
	{
		uci_unload(ctx, ssrpkg); //卸载包
	}

	void RenewSSRContext(const std::string& _PackageName)
	{
		uci_unload(ctx, ssrpkg);
		uci_load(ctx, _PackageName.c_str(), &ssrpkg);
	}

	void GenerateAliasHashMap(std::map<size_t, std::string>& alias_secName_mp)
	{
		const char* _typeName = "servers";
		const char* _OptionName = "alias";
		uci_element* e = nullptr;
		uci_foreach_element(&ssrpkg->sections, e)
		{
			uci_section* s = uci_to_section(e);
			if (!strcmp(s->type, _typeName))
			{
				if (uci_option* opt = GetNamedOption(s, _OptionName))
				{
					size_t hAlias = StrHasher(std::string(opt->v.string));
					std::string secName(std::string(s->e.name));
					alias_secName_mp.emplace(std::move(hAlias),
							std::move(secName));
				}
			}
		}
	}

	void UpdateCurrentSSRConfig(const std::string& _secName,
			FSSRConfig& ssrConfig)
	{
		std::string vAlias;
		ssrConfig.GetAlias(vAlias);

		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "alias", vAlias.c_str());
		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "server", ssrConfig.server.c_str());
		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "server_port", ssrConfig.port.c_str());
		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "password", ssrConfig.password.c_str());
		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "encrypt_method", ssrConfig.method.c_str());
		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "protocol", ssrConfig.protocol.c_str());
		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "protocol_param",
				ssrConfig.protoparam.c_str());
		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "obfs", ssrConfig.obfs.c_str());
		uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_CHANGE,
				_secName.c_str(), "obfs_param", ssrConfig.obfsparam.c_str());
	}

	void AddSSRConfig(FSSRConfig& ssrConfig)
	{
		uci_section* newsection = nullptr;
		uci_add_section(ctx, ssrpkg, "servers", &newsection);
		std::string newsecName = newsection->e.name;
		UpdateCurrentSSRConfig(newsecName, ssrConfig);
	}

	void RemoveAllSSRConfig()
	{
		const char* _typeName = "servers";
		uci_element* e = nullptr;
		uci_foreach_element(&ssrpkg->sections, e)
		{
			uci_section* s = uci_to_section(e);
			if (!strcmp(s->type, _typeName))
			{
				uci_add_delta(&ssrpkg->delta, uci_command::UCI_CMD_REMOVE,
						s->e.name, nullptr, nullptr);
			}
		}
		uci_commit(ctx, &ssrpkg, false);
	}

	void Commit()
	{
		uci_commit(ctx, &ssrpkg, false); //提交保存更改
	}

private:

	uci_package* ssrpkg = nullptr;

};

class FSSRSubscriber
{
public:

	static void RunSubscribe(const std::string& SSRSubFilePath,
			const std::string& dns)
	{
		//	1）下载订阅文件，解析为配置列表
		//	2）迭代所有ssr配置，增量更新对应group的服务器
		//	生成alias-cfgname 映射表
		//	查询新订阅配置和映射表键值的对应关系
		//	重复则覆盖，不存在则添加

		std::vector<FSSRConfig> ssrcfgArray;
		FSSRFileParser::DecodeSSRFile(SSRSubFilePath, dns, ssrcfgArray);

		FSSRCFGAccesser ssrcfgAccesser;
		std::map<size_t, std::string> aliasHash_map;
		ssrcfgAccesser.GenerateAliasHashMap(aliasHash_map);

		for (size_t i = 0, n = ssrcfgArray.size(); i < n; ++i)
		{
			std::string Alias;
			ssrcfgArray[i].GetAlias(Alias);
			auto IT = aliasHash_map.find(StrHasher(Alias));
			if (IT != aliasHash_map.end())
			{
				ssrcfgAccesser.UpdateCurrentSSRConfig((*IT).second,
						ssrcfgArray[i]);
				aliasHash_map.erase(IT);
			}
			else
			{
				ssrcfgAccesser.AddSSRConfig(ssrcfgArray[i]);
			}
		}
		ssrcfgAccesser.Commit();
	}

private:

};

class FCMDParser
{
public:

	static void Parse(int argc, char *argv[])
	{
		std::string ssrFilepath;
		std::string ssrsubURL;
		std::string queryDNS("127.0.0.1");
		bool deletetempfile = false;

		char opt;
		while ((opt = getopt(argc, argv, "f:u:d:xc")) != -1)
		{
			switch (opt)
			{
			case 'f':			//		从指定文件进行订阅
			{
				ssrFilepath = optarg;
				break;
			}
			case 'u':			//		从指定URL下载订阅文件
			{
				ssrsubURL = optarg;
				break;
			}
			case 'd':			//		用于解析域名的dns服务器地址
			{
				queryDNS = optarg;
				break;
			}
			case 'x':			//		订阅完成后删除临时文件
			{
				deletetempfile = true;
				break;
			}
			case 'c':			//		清除现有配置
			{
				FSSRCFGAccesser ssracc;
				ssracc.RemoveAllSSRConfig();
				std::cout << "All server configs removed." << std::endl;
				break;
			}
			}
		}

		if (ssrFilepath.size() > 0)
		{
			if (ACCESS(ssrFilepath.c_str(),4) != -1)
			{
				RunSubscribe(ssrFilepath, queryDNS, deletetempfile);
			}
			else
			{
				std::cout << "Failed,subscribe file not accessable."
						<< std::endl;
			}

		}
		else if (ssrsubURL.size() > 0)
		{
			std::string downloadDir("/tmp/downloads/");
			std::string DLFilename("ssrsub.txt");
			std::string ssrfileDLpath(downloadDir);
			ssrfileDLpath.append(DLFilename);
			std::remove(ssrfileDLpath.c_str());

			std::string DLcmd;
			DLcmd.append("mkdir -p \"");
			DLcmd.append(downloadDir);
			DLcmd.append("\" && wget -q --no-check-certificate -O \"");
			DLcmd.append(ssrfileDLpath);
			DLcmd.append("\" \"");
			DLcmd.append(ssrsubURL);
			DLcmd.append("\"");

			//std::cout << DLcmd << std::endl;
			ssrsub::ExecShell(DLcmd.c_str());
			if (ACCESS(ssrfileDLpath.c_str(),4) != -1)
			{
				RunSubscribe(ssrfileDLpath, queryDNS, deletetempfile);
			}
			else
			{
				std::cout << "Failed,subscribe file download failed."
						<< std::endl;
			}
		}
		else
		{
			std::cout << "Failed,no subscribe data." << std::endl;
		}
	}

private:

	inline static void RunSubscribe(const std::string& ssrFilepath,
			const std::string& dns,
			bool removessrFile = false)
	{
		/*std::string beginmsg("Processing ssrfile '");
		 beginmsg.append(ssrFilepath);
		 beginmsg.append("'");
		 std::cout << beginmsg << std::endl;*/
		FSSRSubscriber ssrSubscriber;
		ssrSubscriber.RunSubscribe(ssrFilepath, dns);
		if (removessrFile)
		{
			std::remove(ssrFilepath.c_str());
		}
		std::cout << "Finished." << std::endl;
	}

};

#endif /* UCIACCESS_H_ */
