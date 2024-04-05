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
    short indexPage[2] = { 0, 0 };
    Ui::SynchAsynchEncryptionClass ui;

    void mainPage();
    void exitButtonPush();
    void encryptPage();
    void decryptPage();
    void electronicSignaturePage();
    void settingsPage();
    void backPage();

    void indexPageSwap(short index);
};
