// BlockCipher.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<camellia.h>
#include<osrng.h>
#include<secblock.h>
#include<files.h>
#include<filters.h>
#include<hex.h>
#include<modes.h>
#include<eax.h>
#include<aes.h>
#include<gcm.h>

using namespace std;
using namespace CryptoPP;

void test_eax() 
{
    string plain = "hunter did this", cipher, recover;
    SecByteBlock key, iv;
    AutoSeededRandomPool prng;
	// EAX mode encryption 
	try
	{
		EAX<Camellia>::Encryption enc;
        key.resize(enc.DefaultKeyLength());
        iv.resize(enc.DefaultIVLength());
        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, iv.size());

		enc.SetKeyWithIV(key, key.size(), iv, iv.size());
		StringSource ssEnc(plain, true,
			new AuthenticatedEncryptionFilter(
				enc,
				new StringSink(cipher)
			));
		cout << endl << "cipher: ";
		StringSource encout(cipher, true,
			new HexEncoder(
				new FileSink(cout)));

		// decryption 
		EAX<Camellia>::Decryption dec;
		dec.SetKeyWithIV(key, key.size(), iv, iv.size());
		StringSource ssDec(cipher, true,
			new AuthenticatedDecryptionFilter(dec,
				new StringSink(recover)));
		cout << endl << "plain : ";
		StringSource decout(recover, true,
			new FileSink(cout));
	}
	catch (const Exception* e)
	{

	}
}

void hexout(const CryptoPP::byte* msg,int len,const string& tag)
{
    cout << endl << tag << ": ";
    StringSource ssout(msg,len, true,
        new HexEncoder(new FileSink(cout)));
    cout << endl;
}

void test_gcm()
{
    GCM<AES>::Encryption aes_gcm_enc;
    GCM<AES>::Decryption aes_gcm_dec;
    SecByteBlock key(32), iv(aes_gcm_enc.DefaultIVLength());
    cout << endl<<"AES gcm default iv length: " << aes_gcm_enc.DefaultIVLength() << endl<<"cipher:";
    
    string cipher, plain = "Encrypted by aes gcm";  // 待加密的数据
    string tag = "Hunter's tag";


    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
    hexout((CryptoPP::byte*)plain.c_str(),plain.size(),"plain");
    hexout(key,key.size(),"gcm key");
    hexout(iv,iv.size(),"gcm iv");
    
    aes_gcm_enc.SetKeyWithIV(key, key.size(), iv, iv.size());
    aes_gcm_dec.DecryptAndVerify()
    //aes_gcm_enc.EncryptAndAuthenticate()
    aes_gcm_dec.SetKeyWithIV(key, key.size(), iv, iv.size());
    

    StringSource ssP(plain, true,
        new AuthenticatedEncryptionFilter(
            aes_gcm_enc,
                new StringSink(cipher)
        ));
    cout << "cipher:" << endl;
    StringSource ssC(cipher, true,
        new HexEncoder(new FileSink(cout)));

    cout << endl << "begin decryption:" << endl;
    StringSource dec(cipher, true,
        new AuthenticatedDecryptionFilter(
            aes_gcm_dec,
            new FileSink(cout)
        ));

}

int main()
{
    // CBC mode encryption 
    Camellia::Encryption cam_enc;
    cout << "default key len " << cam_enc.DefaultKeyLength() << endl;
    cout << "max key len " << cam_enc.MaxKeyLength() << endl;
    cout << "min key len " << cam_enc.MinKeyLength() << endl;
    cout << "block length " << cam_enc.BlockSize() << endl;

    AutoSeededRandomPool prng;
    SecByteBlock key,iv;
    string plain = "enc is good ";

    string cipher, recover;
    try
    {
        CBC_Mode<Camellia>::Encryption enc;
        CBC_Mode<Camellia>::Decryption dec;
		cout << "default key len " << enc.DefaultKeyLength() << endl;
		cout << "max key len " << enc.MaxKeyLength() << endl;
		cout << "min key len " << enc.MinKeyLength() << endl;
        cout << "min iv len " << enc.MinIVLength() << endl;
        cout << "max iv len " << enc.MaxIVLength() << endl;
        cout << "plain in hex: " << endl;
        StringSource ssout(plain, true, new HexEncoder(new FileSink(cout)));
        key.resize(enc.DefaultKeyLength());
        iv.resize(enc.DefaultIVLength());
        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, iv.size());
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());

        StringSource senc(plain, true, new StreamTransformationFilter(enc,
			new StringSink(cipher)));
        cout << "cipher: " << endl;
        ArraySource asout(cipher, true,
            new HexEncoder(
                new FileSink(cout)
            ));


        StringSource sdec(cipher, true, new StreamTransformationFilter(dec,
            new StringSink(recover)));
        cout << "decryption: " << recover << endl;


    }
    catch (const Exception  * e)
    {
    }

    cout << endl << " test eax" << endl;
    test_eax();
    test_gcm();
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
