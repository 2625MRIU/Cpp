#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

using namespace CryptoPP;
using namespace std;

class SecureFileTool {
private:
    static const int KEY_SIZE = AES::MAX_KEYLENGTH; 
    static const int IV_SIZE = 12; 
    static const int SALT_SIZE = 16;
    static const int ITERATIONS = 100000;

    
    void DeriveKey(const string& password, SecByteBlock& key, SecByteBlock& salt) {
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
        pbkdf2.DeriveKey(key.data(), key.size(), 0, (byte*)password.data(), password.size(), salt.data(), salt.size(), ITERATIONS);
    }

public:
    void EncryptFile(const string& inputFile, const string& outputFile, const string& password) {
        AutoSeededRandomPool prng;
        
        SecByteBlock salt(SALT_SIZE);
        SecByteBlock iv(IV_SIZE);
        prng.GenerateBlock(salt, salt.size());
        prng.GenerateBlock(iv, iv.size());

        SecByteBlock key(KEY_SIZE);
        DeriveKey(password, key, salt);

        try {
            ofstream out(outputFile, ios::binary);
            out.write((char*)salt.data(), salt.size());
            out.write((char*)iv.data(), iv.size());

            GCM<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

            FileSource fs(inputFile.c_str(), true,
                new AuthenticatedEncryptionFilter(encryptor,
                    new FileSink(out)
                )
            );
            cout << "Encryption successful: " << outputFile << endl;
        } catch (const Exception& e) {
            cerr << "Encryption Error: " << e.what() << endl;
        }
    }

    void DecryptFile(const string& inputFile, const string& outputFile, const string& password) {
        try {
            ifstream in(inputFile, ios::binary);
            SecByteBlock salt(SALT_SIZE);
            SecByteBlock iv(IV_SIZE);

            in.read((char*)salt.data(), salt.size());
            in.read((char*)iv.data(), iv.size());

            SecByteBlock key(KEY_SIZE);
            DeriveKey(password, key, salt);

            GCM<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

            FileSource fs(in, true,
                new AuthenticatedDecryptionFilter(decryptor,
                    new FileSink(outputFile.c_str())
                )
            );
            cout << "Decryption successful: " << outputFile << endl;
        } catch (const Exception& e) {
            cerr << "Decryption Error (Incorrect password or corrupted file): " << e.what() << endl;
        }
    }
};

int main() {
    SecureFileTool tool;
    
    
    string passwd;
    string file, result;

    do{
    	int choice;
    	cout<<"Select an option\n1)Encrypt file\n2)Decrypt file\n0)Exit\nSelection:"; cin>>choice;
    	switch(choice){
    		case 1:
    			cout<<"Input Path (with extension):";	cin>>file;
    			cout<<"Output Path(with extension .enc):"; cin>>result;
    			cout<<"Enter password: "; 				cin>>passwd;
    			tool.EncryptFile(file , result, passwd);
    			break;
    		case 2:
    			cout<<"Input Path (with extension .enc):";	 cin>>file;
    			cout<<"Output Path (with extension):"; cin>>result;
    			cout<<"Enter password: "; 				 cin>>passwd;
    			tool.DecryptFile(file, result, passwd);
    			break;
    		case 0:
    			cout<<"Program has been terminated\n";
    			exit(0);
    			break;
    		default:
    			cout<<"Invalid choice";
		}
	}while(1);
    

    return 0;
}