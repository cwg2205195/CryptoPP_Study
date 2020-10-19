// Sign.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <osrng.h>
#include <rw.h>
#include<sha3.h>
#include<hex.h>
#include<pssr.h>
#include<files.h>
#include<string>

#include<eccrypto.h>
#include<oids.h>

using namespace std;
using namespace  CryptoPP;


int main()
{
    //  **********************  RWSS ********************** 
    try
    {
        AutoSeededRandomPool prng;
        RW::PrivateKey prikey;
        prikey.GenerateRandomWithKeySize(prng, 1024);
        RW::PublicKey pubkey(prikey);
        cout << "prikey: ";
        prikey.Save(HexEncoder(new FileSink(cout)).Ref());
        cout << endl << "pubkey: ";
        pubkey.Save(HexEncoder(new FileSink(cout)).Ref());
        cout << endl;

        // 验证安全级别
        if (prikey.Validate(prng, 3))
            cout << "private key met crypto standard." << endl;
        else
            cout << "private key doesn't meet crypto standard" << endl;
        if (pubkey.Validate(prng, 3))
            cout << "public key met crypto standard." << endl;
        else
            cout << "public key doesn't meet crypto standard" << endl;

        string plain = "I like cryptography.", signature, recover;
        RWSS<PSSR, SHA3_384>::Signer sig(prikey);
        RWSS<PSSR, SHA3_384>::Verifier ver(pubkey);

        // 签名数据
        StringSource ssPlain(plain, true,
            new SignerFilter(prng, sig,
                new StringSink(signature)));
        cout << endl << "Signature:";
        StringSource ssSig(signature, true,
            new HexEncoder(new FileSink(cout)));

        // 验证签名
        StringSource ssVer(plain + signature, true,
            new SignatureVerificationFilter(ver,
                new StringSink(recover),
                SignatureVerificationFilter::PUT_MESSAGE |
                SignatureVerificationFilter::THROW_EXCEPTION));
        cout << endl << "recover: ";
        StringSource ssOut(recover, true,
            new FileSink(cout));




        cout << endl<<"********************** RWSS *********************"<<endl;
    } 
    catch ( Exception* e)
    {
    }

    cout<<endl<< "  ********************* ECNR *********************" ;
    try
    {
        // 创建公钥、私钥
        AutoSeededRandomPool prng;
        ECNR<ECP, SHA256>::PrivateKey prikey;
        ECNR<ECP, SHA256>::PublicKey pubkey;
        prikey.Initialize(prng, ASN1::secp160r1());
        CRYPTOPP_ASSERT(prikey.Validate(prng, 3));
        prikey.MakePublicKey(pubkey);
        CRYPTOPP_ASSERT(pubkey.Validate(prng, 3));
        string msg = "I like cryptography",signature,recover;

        // 创建签名、验证签名对象
        ECNR<ECP, SHA256>::Signer sig(prikey);
        ECNR<ECP, SHA256>::Verifier ver(pubkey);
        StringSource ssPlain(msg, true,
            new SignerFilter(prng, sig,
                new StringSink(signature), true));
        cout << endl << "signature: ";
        StringSource ssOut(signature, true,
            new HexEncoder(
                new FileSink(cout)
            ));

        // 验证签名
        StringSource ssSig(signature, true,
            new SignatureVerificationFilter(ver,
                new StringSink(recover),
                SignatureVerificationFilter::PUT_MESSAGE |
                SignatureVerificationFilter::THROW_EXCEPTION));
        cout << endl << "recover: ";
        StringSource ssRec(recover, true,
            new FileSink(cout));


        

    }
    catch (const std::exception&)
    {

    }

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
