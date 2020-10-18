// HMAC.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<osrng.h>
#include <secblock.h>
#include<filters.h>
#include<hex.h>
#include<files.h>
#include<string>
#include<hmac.h>
#include<sha3.h>
#include<aes.h>
#include<modes.h>

using namespace std;
using namespace CryptoPP;

int main()
{
	string msg = "you have been hacked";
	string cipher, recoer;
	HMAC<SHA1> hmac;
	SecByteBlock hkey(hmac.DefaultKeyLength());
	AutoSeededRandomPool prng;

	memcpy_s(hkey, hkey.size(), "0123456798abcdef", 16);
	//prng.GenerateBlock(hkey, hkey.size());
	hmac.SetKey(hkey, hkey.size());
	cout << endl << "hmac key: ";
	StringSource tmp3(hkey, hkey.size(), true,
		new HexEncoder(
			new FileSink(cout)
		));

	CBC_Mode<AES>::Encryption cbc_aes_enc;
	CBC_Mode<AES>::Decryption cbc_aes_dec;
	SecByteBlock key_aes(cbc_aes_enc.DefaultKeyLength()), iv_aes(cbc_aes_enc.DefaultIVLength());

	prng.GenerateBlock(key_aes, key_aes.size());
	prng.GenerateBlock(iv_aes, iv_aes.size());
	cbc_aes_enc.SetKeyWithIV(key_aes, key_aes.size(), iv_aes, iv_aes.size());
	cbc_aes_dec.SetKeyWithIV(key_aes, key_aes.size(), iv_aes, iv_aes.size());
	cout << endl << "key: ";
	StringSource tmp1(key_aes, key_aes.size(), true,
		new HexEncoder(
			new FileSink(cout)
		));
	cout << endl << "iv: ";
	StringSource tmp2(iv_aes, iv_aes.size(), true,
		new HexEncoder(
			new FileSink(cout)
		));

	StringSource ss(
		msg,true,
		new StreamTransformationFilter(
			cbc_aes_enc,
			new HashFilter(
				hmac,
				new StringSink(cipher),
				true
			)
		)
	);
	cout << endl << "cipher: ";
	StringSource scipher(
		cipher, true,
		new HexEncoder(new FileSink(cout))
	);

	StringSource sdec(
		cipher, true,
		new HashVerificationFilter(
			hmac,
			new StreamTransformationFilter(
				cbc_aes_dec,
				new StringSink(recoer)
			),
			HashVerificationFilter::HASH_AT_END |
			HashVerificationFilter::PUT_MESSAGE |
			HashVerificationFilter::THROW_EXCEPTION
		)
	);
	cout << endl << "recover: ";
	StringSource recout(recoer, true,
		new HexEncoder(
			new FileSink(cout)
		));


}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
