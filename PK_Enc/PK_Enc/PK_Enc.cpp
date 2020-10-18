// PK_Enc.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#pragma comment(lib,"I:\\Git\\cryptopp\\Win32\\Output\\Release\\cryptlib.lib")
#include <osrng.h>
#include <rsa.h>
#include<hex.h>
#include<files.h>
#include<filters.h>
#include<string>
#include<base64.h>
#include<ecp.h>
#include<oids.h>
#include<eccrypto.h>

using namespace CryptoPP;
using namespace CryptoPP::ASN1;
using namespace std;

void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key);
int main()
{
    // ******************** 非集成 RSA 加密 ********************
    try
    {
        AutoSeededRandomPool prng;
        InvertibleRSAFunction rsa_param;
        rsa_param.GenerateRandomWithKeySize(prng, 1024);
        Integer n = rsa_param.GetModulus();
        Integer p = rsa_param.GetPrime1();
        Integer q = rsa_param.GetPrime2();
        Integer d = rsa_param.GetPrivateExponent();
        Integer e = rsa_param.GetPublicExponent();
        cout << "n( " << n.BitCount() << " ):" << n << endl;
        cout << "p( " << p.BitCount() << " ):" << p << endl;
        cout << "q( " << q.BitCount() << " ):" << q << endl;
        cout << "e( " << e.BitCount() << " ):" << e << endl;
        cout << "d( " << d.BitCount() << " ):" << d << endl;

        string plain = "Encryption using rsa",cipher,recover;
        RSA::PrivateKey prikey(rsa_param);
        RSA::PublicKey pubkey(prikey);
        RSAES_PKCS1v15_Encryptor enc(pubkey);

        StringSource ssPlain(plain, true,
            new PK_EncryptorFilter(prng, enc,
                new StringSink(cipher)));
        cout << endl << "cipher: ";
        StringSource ssCipher(cipher,true,
            new Base64Encoder(new FileSink(cout)));

        RSAES_PKCS1v15_Decryptor dec(prikey);
        StringSource ssDec(cipher, true,
            new PK_DecryptorFilter(prng, dec,
                new StringSink(recover)));
        cout << endl << "recover:";
        StringSource ssDecOut(recover, true,
            new Base64Encoder(new FileSink(cout)));

    }
    catch (Exception* e)
    {
    }
    // ******************** 非集成 RSA 加密 ********************

    // ******************** 集成 ECIES  加密 ********************
    cout << endl << "******************** 集成 ECIES  加密 ********************" << endl;
    try
    {
        AutoSeededRandomPool prng;
        DL_PrivateKey_EC<ECP> ecies_param;
        ecies_param.Initialize(prng, ASN1::secp160r1());
        PrintPrivateKey(ecies_param);

        // 用私钥对象构造解密对象
        ECIES<ECP, SHA1, NoCofactorMultiplication, true, true>::Decryptor dec(ecies_param);
        // 构造加密对象
        ECIES<ECP, SHA1, NoCofactorMultiplication, true, true>::Encryptor enc(dec);
        string plain("We need asymmetric encryption algorithm"),cipher,recover;

        // 加密
        StringSource ssPlain(plain, true,
            new PK_EncryptorFilter(prng, enc,
                new StringSink(cipher)));
        cout << endl << "cipher: ";
        StringSource ssCipherout(cipher, true,
            new Base64Encoder(new FileSink(cout)));

        cout << endl << "Decryption plain:";
        // 解密
        StringSource ssCipher(cipher, true,
            new PK_DecryptorFilter(prng, dec,
                new FileSink(cout)));
    }
    catch (Exception* e)
    {
    }
    // ******************** 集成 ECIES  加密 ********************
}
void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key)
{

}