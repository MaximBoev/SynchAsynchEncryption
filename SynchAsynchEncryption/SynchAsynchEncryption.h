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
    Ui::SynchAsynchEncryptionClass ui;

    void mainPage();
    void encryptPage();
    void decryptPage();
    void electronicSignaturePage();
    void settingsPage();
    void checkKeyPage();
    void checkKeyExitPage();

    void exitButtonPush();
    void encrypt();
    void encryptSynch();
    void encryptAsynch();
    void decrypt();
    void decryptSynch();
    void decryptAsynch();

    int encrypt_(unsigned char* plaintext, int plaintext_len, unsigned char* aad,
        int aad_len, unsigned char* key, unsigned char* iv,
        unsigned char* ciphertext, unsigned char* tag);
    int decrypt_(unsigned char* ciphertext, int ciphertext_len, unsigned char* aad, int aad_len, unsigned char* tag, unsigned char* key, unsigned char* iv, unsigned char* plaintext);
    void handleErrors(void);

    std::string generateRandomKey();
    std::string toHex(const std::string& input);
    std::string base64Encode(const std::string& input);
    std::string base64Decode(const std::string& input);
    std::string hexDecode(const std::string& hex);

};
