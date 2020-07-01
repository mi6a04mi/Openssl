#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf)
{
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open())
    {
        throw std::runtime_error("Can not open file " + filePath);
    }

    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());

    fileStream.close();
}

void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

void AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary | std::ios::app);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

void PasswordToKey(std::string& password)
{
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
        throw std::runtime_error("no such digest");
    }

    const unsigned char* salt = NULL;
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
        reinterpret_cast<unsigned char*>(&password[0]),
        password.size(), 1, key, iv))
    {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
}


void decrypt(std::vector<unsigned char> ciphertext,std::vector<unsigned char> plaintext)
{
    EVP_CIPHER_CTX* ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()));

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv));
    {
        throw std::runtime_error("EncryptInit error");
    }

    std::vector<unsigned char> PlainTextBuf(plaintext.size() + AES_BLOCK_SIZE);
    int PlainTextSize = 0;
    if (1 != EVP_DecryptUpdate(ctx, &PlainTextBuf[0], &PlainTextSize, &plaintext[0], plaintext.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int Lenght = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, &PlainTextBuf[0] + PlainTextSize, &Lenght));
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal error");
    }
    PlainTextSize += Lenght;
    PlainTextBuf.erase(PlainTextBuf.begin() + PlainTextSize, PlainTextBuf.end());

    plaintext.swap(PlainTextBuf);

    EVP_CIPHER_CTX_free(ctx);


}


void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("EncryptInit error");
    }

    std::vector<unsigned char> chipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
    int chipherTextSize = 0;
    if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size())) 
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    
    int lastPartLen = 0;

    if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal error");
    }
    chipherTextSize += lastPartLen;
    chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

    chipherText.swap(chipherTextBuf);

    EVP_CIPHER_CTX_free(ctx);
}

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);

    hash.swap(hashTmp);
}

void Encrypt(std::string plain_text_filepath, std::string chiphertext_path)
{
    std::vector<unsigned char> plainText;
    ReadFile(plain_text_filepath, plainText);

    std::vector<unsigned char> hash;
    CalculateHash(plainText, hash);

    std::vector<unsigned char> chipherText;
    EncryptAes(plainText, chipherText);

    WriteFile(chiphertext_path, chipherText);

    AppendToFile(chiphertext_path, hash);
 }

void Decrypt(std::string plain_text_filepath, std::string chiphertext_path)
{
    std::vector<unsigned char> plainText;
    ReadFile(plain_text_filepath, plainText);

    std::vector<unsigned char> hash_decrypt;
    CalculateHash(plainText, hash_decrypt);

    std::vector<unsigned char> chipherText;
    decrypt(chipherText, plainText);
    WriteFile(chiphertext_path, chipherText);

    AppendToFile(chiphertext_path, hash_decrypt);
}

int main()
{
    std::vector<unsigned char> buf;
    std::string plainText_path = "D:\\plain_text.txt";
    std::string chipher_text_path = "D:\\chipher_text.txt";
    std::string tmp = "D:\\test_file_2";
    Encrypt(plainText_path, chipher_text_path);
    Decrypt(chipher_text_path ,tmp);
}