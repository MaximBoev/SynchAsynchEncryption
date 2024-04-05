#include "SynchAsynchEncryption.h"
#include <openssl/aes.h>
#include <QMessageBox>
SynchAsynchEncryption::SynchAsynchEncryption(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    connect(ui.ExitButton, &QPushButton::clicked, this, &SynchAsynchEncryption::exitButtonPush);
    connect(ui.MExit, &QAction::triggered, this, &SynchAsynchEncryption::exitButtonPush);
    connect(ui.EncryptPageButton, &QPushButton::clicked, this, &SynchAsynchEncryption::encryptPage);
    connect(ui.DecryptPageButton, &QPushButton::clicked, this, &SynchAsynchEncryption::decryptPage);
    connect(ui.ElsectronicSignaturePageButton, &QPushButton::clicked, this, &SynchAsynchEncryption::electronicSignaturePage);
    connect(ui.SettingsPageButton, &QPushButton::clicked, this, &SynchAsynchEncryption::settingsPage);
    connect(ui.MBackPage, &QAction::triggered, this, &SynchAsynchEncryption::backPage);
    connect(ui.MMainPage, &QAction::triggered, this, &SynchAsynchEncryption::mainPage);
    
}

SynchAsynchEncryption::~SynchAsynchEncryption()
{}

void SynchAsynchEncryption::mainPage()
{
    indexPageSwap(0);
    ui.stackedWidget->setCurrentIndex(0);
}

void SynchAsynchEncryption::exitButtonPush()
{
    QMessageBox::StandardButton status = QMessageBox::question(this, "Выход", "Хотите выйти?", QMessageBox::Yes | QMessageBox::No);
    if (status == QMessageBox::Yes) QApplication::quit();
}

void SynchAsynchEncryption::encryptPage()
{
    indexPageSwap(1);
    ui.stackedWidget->setCurrentIndex(1);
}

void SynchAsynchEncryption::decryptPage()
{
    indexPageSwap(2);
    ui.stackedWidget->setCurrentIndex(2);
}

void SynchAsynchEncryption::electronicSignaturePage()
{
    indexPageSwap(3);
    ui.stackedWidget->setCurrentIndex(3);
}

void SynchAsynchEncryption::settingsPage()
{
    indexPageSwap(4);
    ui.stackedWidget->setCurrentIndex(4);
}

void SynchAsynchEncryption::backPage()
{
    if (ui.stackedWidget->currentIndex() == indexPage[0]) {
        mainPage();
    }
    ui.stackedWidget->setCurrentIndex(indexPage[0]);
}

void SynchAsynchEncryption::indexPageSwap(short index)
{
    indexPage[0] = indexPage[1];
    indexPage[1] = index;
}
