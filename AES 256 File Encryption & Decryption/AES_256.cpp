#include <iostream>
#include <fstream>
#include <string>
#include <cstring>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace CryptoPP;

class SecureFileTool {
private:
    static const int KEY_SIZE   = AES::MAX_KEYLENGTH; // 32 bytes
    static const int IV_SIZE    = 12;                 // GCM recommended
    static const int SALT_SIZE  = 16;
    static const int ITERATIONS = 300000;
    static constexpr const char* MAGIC = "SFT1";

    void DeriveKey(const std::string& password,
                   SecByteBlock& key,
                   const SecByteBlock& salt)
    {
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
        pbkdf2.DeriveKey(
            key.data(), key.size(),
            0,
            reinterpret_cast<const byte*>(password.data()),
            password.size(),
            salt.data(), salt.size(),
            ITERATIONS
        );
    }

public:
    void EncryptFile(const std::string& inputFile,
                     const std::string& outputFile,
                     const std::string& password)
    {
        AutoSeededRandomPool prng;

        SecByteBlock salt(SALT_SIZE);
        SecByteBlock iv(IV_SIZE);
        prng.GenerateBlock(salt, salt.size());
        prng.GenerateBlock(iv, iv.size());

        SecByteBlock key(KEY_SIZE);
        DeriveKey(password, key, salt);

        try {
            std::ifstream in(inputFile, std::ios::binary);
            if (!in)
                throw std::runtime_error("Cannot open input file");

            std::ofstream out(outputFile, std::ios::binary);
            if (!out)
                throw std::runtime_error("Cannot open output file");

            /* Write file header */
            out.write(MAGIC, 4);
            out.write(reinterpret_cast<const char*>(salt.data()), salt.size());
            out.write(reinterpret_cast<const char*>(iv.data()), iv.size());

            GCM<AES>::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), iv, iv.size());

            FileSource fs(
                in,
                true,
                new AuthenticatedEncryptionFilter(
                    enc,
                    new FileSink(out)
                )
            );

            SecureWipeBuffer(key.data(), key.size());
        }
        catch (...) {
            SecureWipeBuffer(key.data(), key.size());
            throw;
        }
    }

    void DecryptFile(const std::string& inputFile,
                     const std::string& outputFile,
                     const std::string& password)
    {
        try {
            std::ifstream in(inputFile, std::ios::binary);
            if (!in)
                throw std::runtime_error("Cannot open encrypted file");

            char magic[4];
            in.read(magic, 4);
            if (std::strncmp(magic, MAGIC, 4) != 0)
                throw std::runtime_error("Invalid file format");

            SecByteBlock salt(SALT_SIZE);
            SecByteBlock iv(IV_SIZE);

            in.read(reinterpret_cast<char*>(salt.data()), salt.size());
            in.read(reinterpret_cast<char*>(iv.data()), iv.size());

            SecByteBlock key(KEY_SIZE);
            DeriveKey(password, key, salt);

            GCM<AES>::Decryption dec;
            dec.SetKeyWithIV(key, key.size(), iv, iv.size());

            AuthenticatedDecryptionFilter df(
                dec,
                new FileSink(outputFile.c_str()),
                AuthenticatedDecryptionFilter::THROW_EXCEPTION
            );

            FileSource fs(in, true, new Redirector(df));

            SecureWipeBuffer(key.data(), key.size());
        }
        catch (...) {
            throw;
        }
    }
};



namespace UI {

    void EnableColors() {
    #ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    #endif
    }

    void Clear() {
        std::cout << "\033[2J\033[H";
    }

    void Header() {
        std::cout <<
        "\033[36m"
        "=====================================================\n"
        "        SECURE FILE ENCRYPTION TOOL\n"
        "        AES-256-GCM | PBKDF2-SHA256\n"
        "=====================================================\n"
        "\033[0m\n";
    }

    void Menu() {
        std::cout <<
        "\033[32m"
        "1. Encrypt File\n"
        "2. Decrypt File\n"
        "0. Exit\n"
        "\033[0m\n"
        "Select option: ";
    }

    void Success(const std::string& msg) {
        std::cout << "\033[32mSUCCESS: " << msg << "\033[0m\n";
    }

    void Error(const std::string& msg) {
        std::cout << "\033[31mERROR: " << msg << "\033[0m\n";
    }

    void Pause() {
        std::cout << "\nPress ENTER to continue...";
        std::cin.get();
    }
}

/* ============================================================
   MAIN
   ============================================================ */

int main() {
    UI::EnableColors();
    SecureFileTool tool;

    while (true) {
        UI::Clear();
        UI::Header();
        UI::Menu();

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 0) {
            std::cout << "\nExiting program.\n";
            break;
        }

        std::string inputFile, outputFile, password;

        std::cout << "\nInput file path  : ";
        std::getline(std::cin, inputFile);

        std::cout << "Output file path : ";
        std::getline(std::cin, outputFile);

        std::cout << "Password         : ";
        std::getline(std::cin, password);

        try {
            if (choice == 1) {
                tool.EncryptFile(inputFile, outputFile, password);
                UI::Success("File encrypted successfully");
            }
            else if (choice == 2) {
                tool.DecryptFile(inputFile, outputFile, password);
                UI::Success("File decrypted successfully");
            }
            else {
                UI::Error("Invalid option");
            }
        }
        catch (const std::exception& e) {
            UI::Error(e.what());
        }

        UI::Pause();
    }

    return 0;
}