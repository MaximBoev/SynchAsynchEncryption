#include "SynchAsynchEncryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h >
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <QMessageBox>
#include <QString>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <malloc.h>
#include <memory>
#include <cassert>
#include <cstring>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/engine.h>


SynchAsynchEncryption::SynchAsynchEncryption(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    connect(ui.exitButton, &QPushButton::clicked, this, &SynchAsynchEncryption::exitButtonPush);
    connect(ui.mExit, &QAction::triggered, this, &SynchAsynchEncryption::exitButtonPush);
    connect(ui.encryptPageButton, &QPushButton::clicked, this, &SynchAsynchEncryption::encryptPage);
    connect(ui.decryptPageButton, &QPushButton::clicked, this, &SynchAsynchEncryption::decryptPage);
    connect(ui.electronicSignaturePageButton, &QPushButton::clicked, this, &SynchAsynchEncryption::electronicSignaturePage);
    connect(ui.settingsPageButton, &QPushButton::clicked, this, &SynchAsynchEncryption::settingsPage);
    connect(ui.mMainPage, &QAction::triggered, this, &SynchAsynchEncryption::mainPage);
    connect(ui.mEncryptPage, &QAction::triggered, this, &SynchAsynchEncryption::encryptPage);
    connect(ui.mDecryptPage, &QAction::triggered, this, &SynchAsynchEncryption::decryptPage);
    connect(ui.checkKeyButton, &QPushButton::clicked, this, &SynchAsynchEncryption::checkKeyPage);
    connect(ui.backButton_CKP, &QPushButton::clicked, this, &SynchAsynchEncryption::checkKeyExitPage);
    connect(ui.encryptButton, &QPushButton::clicked, this, &SynchAsynchEncryption::encrypt);
    connect(ui.decryptButton, &QPushButton::clicked, this, &SynchAsynchEncryption::decrypt);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

SynchAsynchEncryption::~SynchAsynchEncryption()
{}

void SynchAsynchEncryption::mainPage()
{
    ui.stackedWidget->setCurrentIndex(0);
}

void SynchAsynchEncryption::exitButtonPush()
{
    QMessageBox::StandardButton status = QMessageBox::question(this, "Выход", "Хотите выйти?", QMessageBox::Yes | QMessageBox::No);
    if (status == QMessageBox::Yes) QApplication::quit();
}

void SynchAsynchEncryption::encrypt()
{
    if (!ui.synchRadioButton_EP->isChecked() && !ui.asynchRadioButton_EP->isChecked()) {
        QMessageBox::warning(this, "Ошибка", "Вы забыли выбрать способ шифровки текста.");
        return;
    }
    if (ui.synchRadioButton_EP->isChecked()) encryptSynch();
    else encryptAsynch();
}

void SynchAsynchEncryption::encryptSynch()
{  
   bool success = true;

    // Получаем с поля ввода текста сам текст, переводим в массив байтов и генерируем ключь.
   QString thisText_QS = ui.plainTextEditInput_EP->toPlainText();
   QByteArray thisText_QBA = thisText_QS.toUtf8();
   QByteArray thisKey_QBA = randomBytes();
   
    // Инициализируем контекст.
   EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    // Инициализация iv.
   unsigned char iv_buffer[EVP_MAX_IV_LENGTH];
   RAND_bytes(iv_buffer, EVP_MAX_IV_LENGTH);
   
    // Инициализаци самого алгоритма контекстом, методом шифровани, ключем и iv.
   if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey_QBA.data()), iv_buffer)) {
       assert(1 != 1);
       success = false;
   }
    // Инициализация необходимых размерных переменных.
   int len = thisText_QBA.size();
   int len_c = len + AES_BLOCK_SIZE;
   int len_f = 0;
   unsigned char* cipher = new unsigned char[len_c];

    // Проверка готовности алгоритма к использованию.
   if (!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL)) {
       assert(2 != 2);
       success = false;
   }

   if (!EVP_EncryptUpdate(ctx, cipher, &len_c, reinterpret_cast<const unsigned char*>(thisKey_QBA.data()), len)) {
       assert(3 != 3);
       success = false;
   }

   if (!EVP_EncryptFinal(ctx, cipher+len_c, &len_f)) {
       assert(4 != 4);
       success = false;
   }
   len = len_c + len_f;

   QByteArray thisEncryptText_QBA;
   if (success) {
       QByteArray tmp_QBA = QByteArray(reinterpret_cast<char*> (cipher), len);
       thisEncryptText_QBA.append(QByteArray(reinterpret_cast<char*>(iv_buffer), EVP_MAX_IV_LENGTH));
       thisEncryptText_QBA.append(tmp_QBA);
   }
   encryptText = thisEncryptText_QBA;
   QString encryptedTextHex_QS = QString(thisEncryptText_QBA.toHex());
   QString thisKeyHex_QS = QString(thisKey_QBA.toHex());
   
   ui.plainTextEditOutput_EP->setPlainText(encryptedTextHex_QS);
   ui.plainTextEditKeySynch->setPlainText(thisKeyHex_QS);

   EVP_CIPHER_CTX_free(ctx);
}

void SynchAsynchEncryption::encryptAsynch()
{

}

void SynchAsynchEncryption::decrypt()
{
    if (!ui.synchRadioButton_DP->isChecked() && !ui.asynchRadioButton_DP->isChecked()) {
        QMessageBox::warning(this, "Ошибка", "Вы забыли выбрать способ дешифровки текста.");
        return;
    }
    if (ui.synchRadioButton_DP->isChecked()) decryptSynch();
    else decryptAsynch();
}

void SynchAsynchEncryption::decryptSynch()
{
    bool success = true;

    QString thisEncryptedText_QS = ui.plainTextEditInput_DP->toPlainText();
    QString thisKey_QS = ui.plainTextEditKeySynch->toPlainText();
    
    std::string thisEncryptedText_S = hexDecode(thisEncryptedText_QS.toStdString());
    std::string thisKey_S = hexDecode(thisKey_QS.toStdString());

    QByteArray thisEncryptedText_QBA(thisEncryptedText_S.c_str(), thisEncryptedText_S.length());
    QByteArray thisKey_QBA(thisKey_S.c_str(), thisKey_S.length());

    assert(thisEncryptedText_QBA == encryptText);

    QByteArray ivData_QBA = thisEncryptedText_QBA.mid(0, EVP_MAX_IV_LENGTH);
    QByteArray encryptedTextData_QBA = thisEncryptedText_QBA.mid(EVP_MAX_IV_LENGTH);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey_QBA.data())
        , reinterpret_cast<const unsigned char*>(ivData_QBA.data()))) {
        assert(1 != 1);
        success = false;
    }

    int len = encryptedTextData_QBA.size();
    int len_f = 0;
    int len_p = len;
    unsigned char* decipher = new unsigned char[len_p + AES_BLOCK_SIZE];

    if (!EVP_DecryptUpdate(ctx, decipher, &len_p, reinterpret_cast<const unsigned char*>(encryptedTextData_QBA.data()), len)) {
        assert(2 != 2);
        success = false;
    }

    if (!EVP_DecryptFinal_ex(ctx, decipher + len_p, &len_f)) {
        assert(3 != 3);
        success = false;
    }
    len = len_p + len_f;
    QByteArray thisDecryptedText_QBA;
    
    if (success) {
        thisDecryptedText_QBA = QByteArray(reinterpret_cast<char*>(decipher), len);
    }

    QString thisDecryptedText_QS = thisDecryptedText_QBA.toBase64();
    ui.plainTextEditOutput_DP->setPlainText(thisDecryptedText_QS);

    EVP_CIPHER_CTX_free(ctx);
    delete[] decipher;
}

void SynchAsynchEncryption::decryptAsynch()
{

}

QByteArray SynchAsynchEncryption::randomBytes()
{
    unsigned char* arr;
    int length = EVP_CIPHER_key_length(EVP_aes_256_cbc());
    arr = new unsigned char[length];
    RAND_bytes(arr, length);
    QByteArray result(reinterpret_cast<char*>(arr), length);
    delete[] arr;
    return result;
}

std::string SynchAsynchEncryption::generateRandomKey() {
    unsigned char* key;
    int key_length = EVP_CIPHER_key_length(EVP_aes_256_cbc());
    key = new unsigned char[key_length];
    RAND_bytes(key, key_length);
    return std::string(reinterpret_cast<const char*>(key), key_length);
}

QByteArray SynchAsynchEncryption::generateRandomIV() {
    unsigned char iv_buffer[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv_buffer, EVP_MAX_IV_LENGTH);
    return QByteArray(reinterpret_cast<const char*>(iv_buffer), EVP_MAX_IV_LENGTH);
}

std::string SynchAsynchEncryption::toHex(const std::string& input)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : input) {
        ss << std::setw(2) << static_cast<unsigned int>(c);
    }
    return ss.str();
}

std::string SynchAsynchEncryption::base64Encode(const std::string& input) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::string SynchAsynchEncryption::base64Decode(const std::string& input) {
    BIO* bio, * b64;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    bio = BIO_push(b64, bio);

    std::string result;
    const int bufferSize = 1024;
    char buffer[bufferSize];
    int bytesRead;

    while ((bytesRead = BIO_read(bio, buffer, bufferSize)) > 0) {
        result.append(buffer, bytesRead);
    }

    BIO_free_all(bio);
    return result;
}

std::string SynchAsynchEncryption::hexDecode(const std::string& hex)
{
    std::string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

void SynchAsynchEncryption::encryptPage()
{
    ui.stackedWidget->setCurrentIndex(1);
}

void SynchAsynchEncryption::decryptPage()
{
    ui.stackedWidget->setCurrentIndex(2);
}

void SynchAsynchEncryption::electronicSignaturePage()
{
    ui.stackedWidget->setCurrentIndex(4);
}

void SynchAsynchEncryption::settingsPage()
{
    ui.stackedWidget->setCurrentIndex(5);
}

void SynchAsynchEncryption::checkKeyPage()
{
    ui.stackedWidget->setCurrentIndex(3);
}

void SynchAsynchEncryption::checkKeyExitPage()
{
    ui.stackedWidget->setCurrentIndex(2);
}
