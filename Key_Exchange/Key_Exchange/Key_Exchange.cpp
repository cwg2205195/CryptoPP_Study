// Key_Exchange.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<integer.h>
#include<osrng.h>
#include<nbtheory.h>	// PrimeAndGenerator
#include<dh.h>

// ecmqd
#include<oids.h>		// secp256r1()
#include<asn.h>
#include<string>
#include<eccrypto.h>		// ecmqv 
#include<ecp.h>
using namespace std	;
using namespace CryptoPP;
using namespace CryptoPP::ASN1;

int main()
{
	// ****************** DH key exchange ******************
	cout << "// ****************** DH key exchange ******************" << endl;
	AutoSeededRandomPool prng;
	Integer p, q, g;
	PrimeAndGenerator pg;
	// generate p = r * q + 1
	pg.Generate(1, prng, 512, 511);
	p = pg.Prime();
	q = pg.SubPrime();
	g = pg.Generator();

	// define two DH object
	DH dhA(p, q, g), dhB(p, q, g);
	SecByteBlock dhA_pri(dhA.PrivateKeyLength());
	SecByteBlock dhA_pub(dhA.PublicKeyLength());
	SecByteBlock dhB_pri(dhB.PrivateKeyLength());
	SecByteBlock dhB_pub(dhB.PublicKeyLength());

	// generate public and private key for A and B
	dhA.GenerateKeyPair(prng, dhA_pri, dhA_pub);
	dhB.GenerateKeyPair(prng, dhB_pri, dhB_pub);

	if (dhA.AgreedValueLength() == dhB.AgreedValueLength())
		cout << "the key length is equal"<<endl;
	else
	{
		cout << "key length not match" << endl;
		return 0;
	}
	SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());
	if (dhA.Agree(sharedA, dhA_pri, dhB_pub))
		cout << "[+]A has the shared key" << endl;
	if (dhB.Agree(sharedB, dhB_pri, dhA_pub))
		cout << "[+]B has the shared key" << endl;

	Integer A, B;
	A.Decode(sharedA.BytePtr(), sharedA.size());
	B.Decode(sharedB.BytePtr(), sharedB.size());

	cout << "A:" << A << endl;
	cout << "B:" << B << endl;


	// ****************** DH key exchange ******************

	// ****************** ECMQV ******************
	cout << endl << "****************** ECMQV ******************" << endl;
	try
	{
		OID curve = secp256r1();	// acquire ANS.1 标准椭圆曲线参数
		AutoSeededRandomPool prng;
		ECMQV<ECP>::Domain mqvA(curve), mqvB(curve);	// 两个秘钥协商对象
		// 长期秘钥对
		SecByteBlock mqvA_stpri(mqvA.StaticPrivateKeyLength()),
			mqvA_stpub(mqvA.StaticPublicKeyLength());
		// 临时秘钥对
		SecByteBlock mqvA_eppri(mqvA.EphemeralPrivateKeyLength()),
			mqvA_eppub(mqvA.EphemeralPublicKeyLength());

		SecByteBlock mqvB_stpri(mqvB.StaticPrivateKeyLength()),
			mqvB_stpub(mqvB.StaticPublicKeyLength());
		SecByteBlock mqvB_eppri(mqvB.EphemeralPrivateKeyLength()),
			mqvB_eppub(mqvB.EphemeralPublicKeyLength());

		mqvA.GenerateStaticKeyPair(prng, mqvA_stpri, mqvA_stpub);
		mqvA.GenerateEphemeralKeyPair(prng, mqvA_eppri, mqvA_eppub);
		mqvB.GenerateStaticKeyPair(prng, mqvB_stpri, mqvB_stpub);
		mqvB.GenerateEphemeralKeyPair(prng, mqvB_eppri, mqvB_eppub);

		if (mqvA.AgreedValueLength() == mqvB.AgreedValueLength())
			cout << "shared key got." << endl;

		SecByteBlock sharedA(mqvA.AgreedValueLength()), sharedB(mqvB.AgreedValueLength());
		if (mqvA.Agree(sharedA, mqvA_stpri, mqvA_eppri, mqvB_stpub, mqvB_eppub))
			cout << "[+]A has shared key" << endl;
		if (mqvB.Agree(sharedB, mqvB_stpri, mqvB_eppri, mqvA_stpub, mqvA_eppub))
			cout << "[+]B has shared key" << endl;

		Integer A, B;
		A.Decode(sharedA.BytePtr(), sharedA.size());
		B.Decode(sharedB.BytePtr(), sharedB.size());
		cout << "A: " << A << endl;
		cout << "B: " << B << endl;
	}
	catch (const std::exception&)
	{

	}
	

	// ****************** ECMQV ******************
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
