// studyHashs.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<channels.h>
#include<string>
#include<files.h>
#include<sha.h>
#include<filters.h>
#include<hex.h>
#include<whrlpool.h>

using namespace std;
using namespace CryptoPP;


int main()
{
    // ************************************** pipling

    string fname = "input.txt";
    string s1, s2, s3, s4;
    SHA1 sha1;
    SHA256 sha256;
    SHA512 sha512;
    Whirlpool whirlpool;

    HashFilter f1(sha1, new HexEncoder(new StringSink(s1)));
    HashFilter f2(sha256, new HexEncoder(new StringSink(s2)));
    HashFilter f3(sha512, new HexEncoder(new StringSink(s3)));
    HashFilter f4(whirlpool, new HexEncoder(new StringSink(s4)));

    ChannelSwitch cs;
    cs.AddDefaultRoute(f1);
    cs.AddDefaultRoute(f2);
    cs.AddDefaultRoute(f3);
    cs.AddDefaultRoute(f4);

    FileSource fs(fname.c_str(), true, new Redirector(cs));
    cout << "SHA1: " << s1 << endl;
    cout << "SHA256: " << s2 << endl;
    cout << "SHA512: " << s3 << endl;
    cout << "Whirlpool: " << s4 << endl;

    // **************************************

    byte buf[1024];
    int len;
    string plain = "You don't know.";
    SHA512 sha_512;
    SecByteBlock digest(sha_512.DigestSize());
    sha_512.Update((byte*)plain.c_str(), plain.length());
    sha_512.Final(digest);
    string digestdump;
    StringSource as(digest.data(),digest.size(), true,
        new HexEncoder(
            new StringSink(digestdump)
        ));
    cout << "sha512 is " << digestdump << endl;

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
