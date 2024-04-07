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

    std::string generateRandomKey();
    std::string toHex(const std::string& input);
    std::string base64Encode(const std::string& input);
    std::string base64Decode(const std::string& input);

};
