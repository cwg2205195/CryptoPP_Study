// PRNG.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
// //*********************      LC_RNG
#include<rng.h>
#include <iostream>
#include <hex.h>
using   namespace std;
using namespace CryptoPP;
#define blockSize 16
#pragma comment(lib,"cryptlib.lib")

//********************* Auto seeded x917 RNG
#include<osrng.h>
#include    <aes.h>
#include<hrtimer.h>
#include <fstream>

// ******************* pipeling *******************
#include<files.h>       // FileSink...
#include<filters.h>     // RandomNumberSource, RandomNumberSink


int main()
{
    ////********************* LC_RNG //*********************
    int seed = 123456;
    LC_RNG rng(seed);
    cout << "RNG algorithm name " << rng.AlgorithmName() << endl;
    cout << "Can Incorporate entropy " << rng.CanIncorporateEntropy() << endl;
    if (rng.CanIncorporateEntropy()) {
        try {
            byte str[] = "my black hole";
            rng.IncorporateEntropy(str, sizeof(str));
        }
        catch (const exception & e) {
            cout << e.what() << endl;
        }
    }
    cout << "generate 1 bit random " << rng.GenerateBit() << endl;
    cout << "generate 1 byte random " << rng.GenerateByte() << endl;

    byte randoms[blockSize + 1];
    string hexout;
    rng.GenerateBlock(randoms, blockSize);
    //for (int j = 0; j < blockSize; ++j) {
    //    printf("%2X ", randoms[j]);
    //}
    StringSource as(randoms,sizeof(randoms), true,
        new HexEncoder(
            new StringSink(hexout),
            true
        ));
    cout << "generated hexs: " << hexout << endl;

    cout << "generate random number in range (100,1000) " << rng.GenerateWord32(100, 1000) << endl;
    
    cout << " mess an array" << endl;
    int arrays[] = {1,2,3,4,5,6,7};
    rng.Shuffle(arrays, arrays + _countof(arrays));
    cout << _countof(arrays) << " - " << sizeof(arrays) << endl;
    for (int i = 0; i < 7; ++i) {
        cout << arrays[i] << " ";
    }
    ////********************* LC_RNG //*********************


    ////********************* AutoSeedX917RNG //*********************
    AutoSeededX917RNG<AES> rng_917;
    ofstream file("randoms.dat", ios_base::binary | ios_base::out);
    byte buf[blockSize];
    Timer tmer;
    tmer.StartTimer();
    printf("Buf size = %d\n", sizeof(buf));
    for (int k = 0; k < 1024; ++k) {
        rng_917.GenerateBlock(buf, sizeof(buf));
        file.write((const char*)buf, blockSize);
    }
    cout << "random data generation finished. Elapsed " << tmer.ElapsedTimeAsDouble() << endl;
    file.close();

    //////********************* Pipeling ....////*********************
    AutoSeededX917RNG<AES> rng_917_;
    string entro = "this is entrophy";
    StringSource ss(entro, true, new RandomNumberSink(rng_917_));
    ofstream file_("data1.dat", ios_base::binary | ios_base::out);
    cout << "[+]Begin generating random..." << endl;
    Timer tim;
    tim.StartTimer();
    for (int l = 0; l < 1024; ++l) {
        RandomNumberSource rss(rng_917_, blockSize, true, new FileSink(file_));
    }
    cout << "file wrote" << endl;
    file_.close();
    ////********************* AutoSeedX917RNG //*********************
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
