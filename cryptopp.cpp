#include <stdio.h>    
#include <iostream>  
#include <fstream>  
#include <sstream>    
#include <cryptopp/aes.h>  
#include <cryptopp/filters.h>  
#include <cryptopp/modes.h>  
  
using namespace std;  
  
static void hexdump(FILE *f, const char *title, const unsigned char *s, int len)
{  
	int n = 0;
	fprintf(f, "%s", title);
	
	for (n = 0; n < len; ++n) 
	{		
        fprintf(f, "%02x", s[n]);  
    }  
	
	/*
    int n = 0;  	
    fprintf(f, "%s", title);  
	
    for (; n < len; ++n) 
	{  
        if ((n % 16) == 0) 
		{  
                fprintf(f, "\n%04x", n);  
        }  
		
        fprintf(f, " %02x", s[n]);  
    }  
  
    fprintf(f, "\n");  
	*/
}

static void hexload(const string &hex_text, string &text)
{
	int i =0;
	while(true)  
    {  
        char c;  
        int x;  
        stringstream ss;  
        ss<<hex<<hex_text.substr(i, 2).c_str();  
        ss>>x;  
        c = (char)x;  
        text += c;  
        if(i >= (int)hex_text.length() - 2)
		{	
			break;  
		}
		
        i += 2;  
    }  	
}
 
string encrypt(byte *key, int key_len, byte *iv, string plainText)
{  
    string cipherText;  
  
    CryptoPP::AES::Encryption aesEncryption(key, key_len);  
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );  
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( cipherText ), CryptoPP::StreamTransformationFilter::ZEROS_PADDING);  
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plainText.c_str() ), plainText.length() + 1);  
    stfEncryptor.MessageEnd();  

	return cipherText;	
}  
  
void writeCipher(string output)  
{  
    ofstream out("/tmp/cipher.data");  
    out.write(output.c_str(), output.length());  
    out.close();  
  
    cout<<"writeCipher finish "<<endl<<endl;  
}  
  
string decrypt(byte *key, int key_len, byte *iv, string cipherTextHex)  
{  
    string decryptedText;  
  
	CryptoPP::AES::Decryption aesDecryption(key, key_len);  
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );  
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedText ), CryptoPP::StreamTransformationFilter::ZEROS_PADDING);  
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>(cipherTextHex.c_str()), cipherTextHex.length());  
    stfDecryptor.MessageEnd();  
  
    return decryptedText;  
}  
  
string readCipher(byte *key, int key_len, byte *iv)  
{  
    ifstream in("/tmp/cipher.data");  
  
    string line;  
    string decryptedText;  
    while(getline(in, line))  
    {  
        if(line.length() > 1)  
        {  
            decryptedText += decrypt(key, key_len, iv, line) + "\n";  
        }  
        line.clear();  
    }  
  
    cout<<"readCipher finish "<<endl;  
    in.close();  
  
    return decryptedText;  
}    
  
int main()  
{  
	char key[16] = "0123456789abcde";
	char iv[16] = "fedcba987654321";  

	cout<<"== rkey ==: "<<key<<endl;
	cout<<"== iv ==: "<<iv<<endl;
    //string text = "12345678901234";  
	string text = "需加密的字符this is a string will be AES_Encrypt";  
    cout<<"== plaintext ==: "<<text<<endl;
  
    string cipherHex = encrypt((byte *)key, sizeof(key), (byte *)iv, text);  
    hexdump(stdout, "== ciphertext ==: ", (unsigned char *)cipherHex.c_str(), cipherHex.length());
	printf("\n");
	
	string text_ret = decrypt((byte *)key, sizeof(key), (byte *)iv, cipherHex);
    cout<<"== checktext1 ==: "<<text_ret<<endl; 
	
	string cipher_hextext = "be12a80f40677182a2e8dd1a6c8cb49f29296b738b7a0a17c6df3baa706c6b1e7de88c1392a6642cf27ffedd026db358b0851e1ce9fea8f2febb599441a93914";
	string cipher_text;
	
	hexload(cipher_hextext, cipher_text);
	string text_ret1 = decrypt((byte *)key, sizeof(key), (byte *)iv, cipher_text);
    cout<<"== checktext2 ==: "<<text_ret1<<endl;
	return 0;  
}  