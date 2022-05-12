#pragma once
#include "process/event.h"
#include "rw_lock.h"

class Tools {

public:
	static std::wstring StringToWString(LPCSTR cs);
	static std::string WString2String(LPCWSTR ws);  //�����ַ�תΪstring
	static ULONG64 String2ULONG64(const std::string& s);
	static int String2Int(const std::string& s);  //��stringת��Ϊint
	static std::string DecInt2HexStr(ULONG64 num);      //ʮ����ת16�����ַ���
	static std::wstring DecInt2HexWStr(ULONG64 num);
	static ULONG64 HexStr2DecInt(std::string);      //ʮ����ת16�����ַ���
	static std::string UnicodeToUtf8(LPCWSTR unicode);      //ʮ����ת16�����ַ���
	static std::string getTimeFromSystemTimeStamp(LARGE_INTEGER timeStamp);
	static std::wstring getProcessNameByPID(ULONG64 pid);
	static ULONG64 getProcessIDByTID(ULONG64 pid);

	static void initVolume2DiskMap();
	static void convertFileNameInDiskFormat(std::string &fileName);
	static std::string parseEventInJsonFormat(const BaseEvent &event);
};

template<typename Key, typename Val>
class ReadWriteMap {

public:
	typedef typename std::map<Key, Val>::iterator this_iterator;
	typedef typename std::map<Key, Val>::const_iterator this_const_iterator;
	typedef typename std::pair< this_iterator, bool> this_pair;

	//Val operator [](const Key& key)
	//{
	//	rwLock.readLock();
	//	auto res = rwMap[key];
	//	rwLock.readUnLock();

	//	return res;
	//}

	Val operator [](const Key& key) 
	{
		rwLock.readLock();
		auto res = rwMap[key];
		rwLock.readUnLock();

		return res;
	}

	//Val operator [](const Key& key)
	//{
	//	Val res;
	//	rwLock.readLock();
	//	if (rwMap.count(key)) {
	//		res = rwMap.find(key)->second;
	//	}
	//	else {
	//		res = rwMap.insert(std::map<Key, Val>::value_type(key, Val())).first->second;
	//		//rwMap.insert(key);
	//	}
	//	//auto res = rwMap[key];
	//	rwLock.readUnLock();

	//	return res;
	//}

	this_iterator find(const Key& key)
	{
		rwLock.readLock();
		auto res = rwMap.find(key);
		rwLock.readUnLock();

		return res;
	}
	this_const_iterator find(const Key& key) const
	{
		rwLock.readLock();
		auto res = rwMap.find(key);
		rwLock.readUnLock();

		return res;
	}

	// used in setFileName(BaseEvent* ev) to avoid undefined behavior, because mutexe needs before iterator.
	Val getValue(const Key& key) {

		Val res;	

		rwLock.readLock();
		if (rwMap.count(key) != 0)	res = rwMap[key];	//if count =0 , return default val
		rwLock.readUnLock();

		return res;
	}
	
	template<typename ValueItem>
	int countValueNumWithKey(const Key& key, const ValueItem& valItem) {

		int valCnt = -1;
		rwLock.readLock();
		//auto it = ;
		if (rwMap.count(key) == 0)	valCnt = -1;
		else {
			valCnt = rwMap[key].count(valItem);  //we can add add pair by operator[] ,though no mapping key-value pair.
		}
		rwLock.readUnLock();

		return valCnt;
	}

	int count(const Key& key)
	{
		rwLock.readLock();
		auto res = rwMap.count(key);
		rwLock.readUnLock();

		return res;
	}

	this_iterator end()
	{
		rwLock.readLock();
		auto res = rwMap.end();
		rwLock.readUnLock();

		return res;
	}

	this_const_iterator end() const
	{
		rwLock.readLock();
		auto res = rwMap.end();
		rwLock.readUnLock();

		return res;
	}

	this_iterator begin()
	{
		rwLock.readLock();
		auto res = rwMap.begin();
		rwLock.readUnLock();

		return res;
	}

	bool empty()
	{
		rwLock.readLock();
		auto res = rwMap.empty();
		rwLock.readUnLock();

		return res;
	}

	template<typename ValueItem>
	int eraseValueItemWithKey(const Key& key,const ValueItem& valItem) {

		//this_iterator nextIt = nullptr;
		int res = 0;
		rwLock.writeLock();
		auto it = rwMap.find(key);
		if (it != rwMap.end())	res = it->second.erase(valItem);
		rwLock.writeUnLock();
		
		return res;
	}

	int erase(const Key& key)
	{
		rwLock.writeLock();
		auto res = rwMap.erase(key);
		rwLock.writeUnLock();

		return res;
	}

	template<typename ValueItem>
	void insertValueItemWithKey(const Key& key, const ValueItem& valItem) {

		rwLock.writeLock();
		auto it = rwMap.find(key);
		if (it != rwMap.end())	it->second.insert(valItem);
		rwLock.writeUnLock();

		//return nextIt;
	}

	//returns old iterator which is overwrited, if the iterator's value is a pointer , user can delete it with return value
	this_pair insertOverwirte(const Key key, const Val value) {

		//Val rtVal;
		rwLock.writeLock();
		auto res = rwMap.insert(typename std::map<Key, Val>::value_type(key, value));

		if (!res.second) {
			//rtVal = res.first->second;
			rwMap.erase(key);
			rwMap.insert(std::map<Key, Val>::value_type(key, value));
		}
		rwLock.writeUnLock();

		return res;
	}

	this_pair insert(const Key key, const Val value) {

		rwLock.writeLock();
		auto res = rwMap.insert(typename std::map<Key, Val>::value_type(key, value));
		rwLock.writeUnLock();

		return res;
	}

private:
	std::map<Key, Val> rwMap;
	RWLock rwLock;
};

int InitProcessMap();

