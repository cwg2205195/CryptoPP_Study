// pbkdf.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<hkdf.h>
#include<osrng.h>
#include<filters.h>
#include<hex.h>
#include<sha3.h>
#include<files.h>
#include<secblock.h>
#include<gcm.h>
#include<eax.h>
#include<aes.h>
#include<sm4.h>
#include<ripemd.h>
#include<pwdbased.h>	// pkcs12 _ pbkdf
#include<string>

using namespace std;
using namespace CryptoPP;


int main()
{
	// ********************* HKDF SHA3 *********************
	// ********************* 生成 128 字节派生秘钥 *********************
	AutoSeededRandomPool prng;
	HKDF<SHA3_512> hkdf;
	// 16 字节盐， 16 字节附加信息， 32字节密文， 128 字节派生秘钥
	SecByteBlock salt(16), info(16), secret(32), derived_key(128);
	prng.GenerateBlock(salt, salt.size());
	prng.GenerateBlock(info, info.size());
	prng.GenerateBlock(secret, secret.size());

	hkdf.DeriveKey(derived_key, derived_key.size(),
		secret, secret.size(),
		salt, salt.size(),
		info, info.size());

	std::cout << "max derivable key length: " << hkdf.MaxDerivedKeyLength() << endl;
	std::cout << "min derivable key length: " << hkdf.MinDerivedKeyLength() << endl;
	std::cout << "valid key length: " << hkdf.GetValidDerivedLength(derived_key.size()) << endl;
	std::cout << "salt:";
	ArraySource as1(salt, salt.size(), true,
		new HexEncoder(new FileSink(std::cout)));
	std::cout << endl << "info: ";
	ArraySource asInfo(info, info.size(), true,
		new HexEncoder(new FileSink(std::cout)));
	std::cout << endl << "secret: ";
	ArraySource asSec(secret, secret.size(), true,
		new HexEncoder(new FileSink(std::cout)));
	std::cout << endl << "derived key: ";
	ArraySource asKey(derived_key, derived_key.size(), true,
		new HexEncoder(new FileSink(std::cout)));
	// ********************* HKDF SHA3 *********************
#define PBKDF_ENC 1
#ifdef PBKDF_ENC

	// ********************* PBKDF *********************
	std::cout << endl << "********************* PBKDF *********************" << endl;
	// 通过用户输入的秘钥推导出主密钥， 主密钥用于加解密工作秘钥，工作秘钥才是真正加解密数据用的。
	try
	{
		string passwd;
		std::cout <<endl<<endl<< "Input password : " << endl;
		getline(cin, passwd);
		AutoSeededRandomPool prng;
		SecByteBlock salt(128);		// salt 需要被存储
		size_t count = 100000;		// 迭代次数
		EAX<SM4>::Encryption eax_sm4_enc;	// 用于加密数据
		GCM<AES>::Encryption gcm_aes_enc;	// 加密 sm4 秘钥 和 iv
		size_t dpk_len = eax_sm4_enc.DefaultKeyLength() + eax_sm4_enc.DefaultIVLength();
		SecByteBlock dpk(dpk_len);
		size_t mk_len = gcm_aes_enc.DefaultKeyLength() + gcm_aes_enc.DefaultIVLength();	// 计算 AES 秘钥、IV长度
		SecByteBlock mk(mk_len);		// 保存 AES Master key

		prng.GenerateBlock(salt, salt.size());
		PKCS12_PBKDF<RIPEMD320> pbkdf;		// 使用 RIPEMD320 作为推导主秘钥的哈希算法
		pbkdf.DeriveKey(mk, mk.size(),
			static_cast<byte>('M'),		// purpose
			(CryptoPP::byte*)passwd.c_str(),passwd.size(),	// 推导主秘钥的密码
			salt,salt.size(),		// 盐
			count,					// 迭代次数
			0.0);
		// 必须保存盐，否则后续无法推导出主密钥
		std::cout << "salt: ";
		ArraySource asSalt(salt, salt.size(), true,
			new HexEncoder(new FileSink(std::cout)));
		// 输出推导的 主密钥……
		std::cout << endl << "Master key:" << endl;
		ArraySource asMK(mk, mk.size(), true,
			new HexEncoder(new FileSink(std::cout)));
		/*
		128 字节 Salt
		48 字节 认证加密的工作秘钥
		*/

		// 生成随机的工作秘钥
		prng.GenerateBlock(dpk, dpk.size());
		string enc_working_key;	// 保存被加密的工作秘钥
		gcm_aes_enc.SetKeyWithIV(mk, gcm_aes_enc.DefaultKeyLength(),
			mk + gcm_aes_enc.DefaultKeyLength(), gcm_aes_enc.DefaultIVLength());	// 设置AES GCM 的秘钥和IV

		// 主密钥加密工作秘钥：
		StringSource ssEncWorking(dpk, dpk.size(), true,
			new AuthenticatedEncryptionFilter(
				gcm_aes_enc,
				new StringSink(enc_working_key)
			));

		std::cout << endl << "working key + iv length = " << dpk.size() << endl << "Sm4 key:";
		ArraySource asDpkOut(dpk, dpk.size(),true,
			new HexEncoder(new FileSink(std::cout)));
		// 输出加密并被认证的工作秘钥 密文
		std::cout << endl << "[+]Authenticated Encrypted Working Key cipher is ";
		StringSource ssEncWoringKey(enc_working_key, true,
			new HexEncoder(
				new FileSink(std::cout)
			));

		// 把盐和加密的工作秘钥导出到文件：
		FileSink encParams("salt_enc_key.txt");
		encParams.Put(salt, salt.size());
		encParams.Put((CryptoPP::byte*)enc_working_key.c_str(), enc_working_key.size());
		encParams.MessageEnd();

		// SM4 加密文件
		eax_sm4_enc.SetKeyWithIV(dpk, eax_sm4_enc.DefaultKeyLength(),
			dpk + eax_sm4_enc.DefaultKeyLength(), eax_sm4_enc.DefaultIVLength());
		// 加密文件
		FileSource fsPlain("test.txt", true,
			new AuthenticatedEncryptionFilter(eax_sm4_enc,
				new FileSink("encrypted_test.txt")));
	}
	catch (const Exception* e)
	{
		std::cout << e->what() << endl;
	}
#endif
	// ********************* 解密 *********************
	std::cout << endl << "********************* 解密 *********************"<<endl<<
		"请输入秘钥："<<endl;

	try
	{
		
		// 读取用户输入的秘钥，打开保存的盐和加密认证数据文件，
		// 用盐和用户输入的秘钥推导主密钥，
		// 主密钥认证并解密末尾的 48 字节 sm4 秘钥数据
		// sm4 算法初始化，解密目标文件

		string passwd;	// 用户输入的秘钥
		getline(cin, passwd);
		EAX<SM4>::Decryption eax_sm4_dec;
		GCM<AES>::Decryption gcm_aes_dec;
		string cipher_param_read;

		// 读取 salt 和 认证加密数据
		FileSource fparam("salt_enc_key.txt", true,		// 是否启用 HexDecoder ？
			new StringSink(cipher_param_read),true);
		cout << "read len:" << cipher_param_read.size() << endl;
		SecByteBlock salt(128);
		memcpy_s(salt, salt.size(), cipher_param_read.c_str(), salt.size());
		std::cout << endl << "salt:";
		ArraySource asSalt1(salt, salt.size(),true,
			new HexEncoder(new FileSink(std::cout)));

		// 推导主密钥
		PKCS12_PBKDF<RIPEMD320> pbkdf;
		SecByteBlock master_key(gcm_aes_dec.DefaultIVLength() + gcm_aes_dec.DefaultKeyLength());
		size_t count = 100000;
		pbkdf.DeriveKey(master_key, master_key.size(),
			static_cast<byte>('M'),
			(CryptoPP::byte*)passwd.c_str(), passwd.size(),
			salt, salt.size(),
			count,
			0.0
		);
		std::cout << endl<< "[+]Master key:";
		ArraySource asKeyout(master_key, master_key.size(),true,
			new HexEncoder(new FileSink(std::cout)));


		// aes gcm 解密初始化
		gcm_aes_dec.SetKeyWithIV(master_key, gcm_aes_dec.DefaultKeyLength(),
			master_key + gcm_aes_dec.DefaultKeyLength(), gcm_aes_dec.DefaultIVLength());

		// 解密 SM4 的工作秘钥
		SecByteBlock sm4_dec_key_iv(eax_sm4_dec.DefaultIVLength() + eax_sm4_dec.DefaultKeyLength());
		//SecByteBlock working_key(cipher_param_read.length() - salt.size());
		//memcpy_s(working_key, working_key.size(), cipher_param_read.c_str() + salt.size(), working_key.size());
		ArraySource asDec((CryptoPP::byte*)cipher_param_read.c_str()+salt.size(),
			cipher_param_read.size()-salt.size(), true,				// ArraySource 一定要加是否 pumpAll 参数，不然会莫名其妙
			new AuthenticatedDecryptionFilter(gcm_aes_dec,
				new ArraySink(sm4_dec_key_iv,sm4_dec_key_iv.size())));
		std::cout << endl << "sm4 key is :" << endl;
		ArraySource asKeyout1(sm4_dec_key_iv, sm4_dec_key_iv.size(),true,
			new HexEncoder(
				new FileSink(std::cout)
			));

		// 初始化 SM4 解密算法
		eax_sm4_dec.SetKeyWithIV(sm4_dec_key_iv, eax_sm4_dec.DefaultKeyLength(),
			sm4_dec_key_iv + eax_sm4_dec.DefaultKeyLength(), eax_sm4_dec.DefaultIVLength());

		// 解密文件
		string recover;
		FileSource s4dec("encrypted_test.txt", true,
			new AuthenticatedDecryptionFilter(				// 注意哦， EAX 是认证加解密
				eax_sm4_dec,
				new StringSink(recover)),true);
		std::cout << endl << "Decrypted:";
		StringSource ssout(recover, true,
			new FileSink(std::cout));
	}
	catch (const Exception* e)
	{
		std::cout << e->what() << endl;
	}
	
	// ********************* PBKDF *********************

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
