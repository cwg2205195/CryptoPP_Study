// StreamCipher.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <salsa.h>
#include<osrng.h>
#include<secblock.h>
#include<hex.h>
#include<iostream>
#include<string>

// chacha20
#include <chacha.h>
#include<Filter.h>
#include<files.h>

using namespace std;
using namespace CryptoPP;
void printBytes(CryptoPP::byte* text,int size,string tag)
{
    string out;
    ArraySource as(text, size, true, new HexEncoder(new StringSink(out)));
    cout << tag<< " hexdump : " << out << endl;
}

void cipher_with_chacha20(string& in_filename,string& out_filename, bool enc_flag)
{
    if (in_filename.empty()||out_filename.empty())
    {
        cout << "failed to open file..." << endl;
    }
    XChaCha20::Encryption enc;
    XChaCha20::Decryption dec;
    AutoSeededRandomPool prng;
    SecByteBlock key(enc.DefaultKeyLength()), iv(enc.DefaultIVLength());

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
    printBytes(key, key.size(), "Key");
    printBytes(iv, iv.size(), "IV");

    enc.SetKeyWithIV(key, key.size(), iv, iv.size());
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

	/*FileSource fsrc(in_filename.c_str(), true);
	FileSink fs(out_filename.c_str());*/
    if (enc_flag) {
        FileSource fsrc(in_filename.c_str(), true,
            new StreamTransformationFilter(enc,
                new FileSink(out_filename.c_str())));
        //StreamTransformationFilter stf(enc,&fs);
        //stf.MessageEnd();
        cout << "file was encrypted." << endl;
    }
    else {
		FileSource fsrc(in_filename.c_str(), true,
			new StreamTransformationFilter(dec,
				new FileSink(out_filename.c_str())));
		/* StreamTransformationFilter stf(dec, &fs);
		 stf.MessageEnd();*/
        cout << "file was encrypted." << endl;
    }


}

int main()
{
    string in("test.txt"), out("enc.dat"),rec("recover.txt");
    cipher_with_chacha20(in,out, true);
    cipher_with_chacha20(out, rec, false);

    // ************************** XSalsa20 **************************
    XSalsa20::Encryption enc;
    XSalsa20::Decryption dec;
    // 默认Key长度 32 字节， IV 长度 24 字节
    cout << "default key length " << enc.DefaultKeyLength() << endl;
    cout << "min key length " << enc.MinKeyLength() << endl;
    cout << "max key length " << enc.MaxKeyLength() << endl;
    cout << "default iv length " << enc.DefaultIVLength() << endl;
    cout << "max iv length " << enc.MaxIVLength() << endl;
    cout << "min iv length " << enc.MinIVLength() << endl;

    AutoSeededRandomPool prng;

    string plain("You have been hacked"), cipher, recover;
    SecByteBlock key(enc.DefaultKeyLength()), iv(enc.DefaultIVLength());
    // 随机生成 Key 和 IV
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
    string tmp;
    ArraySource as(key, key.size(),true, new HexEncoder(new StringSink(tmp)));
    cout << "Key is : " << tmp << endl;
    //
    cout << "can modify input: " << as.CanModifyInput() << endl;
    string tmp1;
    ArraySource as1(iv, iv.size(), true, new HexEncoder(new StringSink(tmp1)));

    cout << "IV is : " << tmp1 << endl;

    // 设置秘钥和iv
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    // 加密 (out, plain, size)
    cipher.resize(plain.size());
    enc.ProcessData((CryptoPP::byte*)cipher.c_str(), (CryptoPP::byte*)plain.c_str(), plain.size());

    //as.PumpAll();
    //as.Put((CryptoPP::byte*)cipher.c_str(), cipher.size());
	string tmp2;
	ArraySource as2(cipher, true, new HexEncoder(new StringSink(tmp2)));
    cout << "cipher is " << tmp2 << endl;

    // 解密 (out, plain, size)
	recover.resize(cipher.size());
    dec.ProcessData((CryptoPP::byte*)recover.c_str(), (CryptoPP::byte*)cipher.c_str(), cipher.size());
	string tmp3;
	ArraySource as3(recover, true, new HexEncoder(new StringSink(tmp3)));
    cout << "recover is " << recover << endl;
    // ************************** XSalsa20 **************************




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
