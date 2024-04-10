#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_SynchAsynchEncryption.h"

class SynchAsynchEncryption : public QMainWindow
{
    Q_OBJECT

public:
    SynchAsynchEncryption(QWidget *parent = nullptr);
    ~SynchAsynchEncryption();

private:
    std::string publicKey;
    std::string privateKey;

    Ui::SynchAsynchEncryptionClass ui;

    void mainPage();
    void encryptPage();
    void decryptPage();
    void electronicSignaturePage();
    void settingsPage();
    void checkKeyPage();
    void checkKeyExitPage();

    void exitButtonPush();
    void GenKey(std::string& str_public_key, std::string& str_private_key);
    bool Encrypt(const std::string rsa_public_key, const std::string source, std::string& dest);
    bool Decrypt(const std::string private_key, const std::string source, std::string& dest);
    void encrypt();
    void encryptSynch();
    void encryptAsynch();
    
    void decrypt();
    void decryptSynch();
    void decryptAsynch();

    QByteArray encryptAES(const QByteArray& plaintext, const QByteArray& key, const QByteArray& iv);
    QByteArray decryptAES(const QByteArray& encryptedText, const QByteArray& key, const QByteArray& iv);

    int encrypt_(unsigned char* plaintext, int plaintext_len, unsigned char* aad,
        int aad_len, unsigned char* key, unsigned char* iv,
        unsigned char* ciphertext, unsigned char* tag);
    int decrypt_(unsigned char* ciphertext, int ciphertext_len, unsigned char* aad, int aad_len, unsigned char* tag, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

    std::string generateRandomKey();
    QByteArray generateRandomIV();
    std::string toHex(const std::string& input);
    std::string base64Encode(const std::string& input);
    std::string base64Decode(const std::string& input);
    std::string hexDecode(const std::string& hex);

};
