#include "SynchAsynchEncryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h >
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <QMessageBox>
#include <QString>
#include <iostream>
#include <iomanip>
#include <sstream>

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
   QString thisText_ = ui.plainTextEditInput_EP->toPlainText();
   std::string thisText = thisText_.toStdString();
   std::string thisKey = generateRandomKey();
   std::string iv;
   EVP_CIPHER_CTX* ctx;
   ctx = EVP_CIPHER_CTX_new();
   EVP_CIPHER_CTX_init(ctx);

   unsigned char iv_buffer[EVP_MAX_IV_LENGTH];
   RAND_bytes(iv_buffer, EVP_MAX_IV_LENGTH);
   iv = std::string(reinterpret_cast<const char*>(iv_buffer), EVP_MAX_IV_LENGTH);

   std::string encrypted_text;

   EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()));

   int cipher_text_len = thisText.length() + EVP_MAX_BLOCK_LENGTH;
   unsigned char* cipher_text = new unsigned char[cipher_text_len];

   int actual_cipher_text_len;

   EVP_EncryptUpdate(ctx, cipher_text, &actual_cipher_text_len, reinterpret_cast<const unsigned char*>(thisText.c_str()), thisText.length());
   encrypted_text.append(reinterpret_cast<const char*>(cipher_text), actual_cipher_text_len);

   delete[] cipher_text;

   EVP_CIPHER_CTX_free(ctx);
   
   std::string base64EncodedText = base64Encode(encrypted_text);
   std::string base64EncodedKey = base64Encode(thisKey);
   
   //toHex(base64EncodedText);

   QString encryptedText = QString::fromStdString(base64EncodedText);
   QString thisKey_ = QString::fromStdString(base64EncodedKey);

   ui.plainTextEditOutput_EP->setPlainText(encryptedText);
   ui.plainTextEditKeySynch->setPlainText(thisKey_);
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
    //QString encryptedText_ = ui.plainTextEditInput_DP->toPlainText();
    //QString thisKey_ = ui.plainTextEditKeySynch->toPlainText();
    //std::string decryptedText_;
    //
    //std::string encryptedText = base64Decode(encryptedText_.toStdString());
    //std::string thisKey = base64Decode(thisKey_.toStdString());
    //
    //std::string iv(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);
    //encryptedText.erase(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);
    //
    //EVP_CIPHER_CTX* ctx;
    //ctx = EVP_CIPHER_CTX_new();
    //EVP_CIPHER_CTX_init(ctx);
    //
    //EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()));
    //
    //int decryptedTextLen = encryptedText.length() + EVP_MAX_BLOCK_LENGTH;
    //unsigned char* decryptedTextBuffer = new unsigned char[decryptedTextLen];
    //
    //int actualDecryptedTextLen;
    //
    //EVP_DecryptUpdate(ctx, decryptedTextBuffer, &actualDecryptedTextLen, reinterpret_cast<const unsigned char*>(encryptedText.c_str()), encryptedText.length());
    //decryptedText_.append(reinterpret_cast<const char*>(decryptedTextBuffer), actualDecryptedTextLen);
    //
    //delete[] decryptedTextBuffer;
    //
    //EVP_CIPHER_CTX_free(ctx);
    //
    //std::string base64EncodedText = base64Encode(decryptedText_);
    //QString decryptedText = QString::fromStdString(base64EncodedText);
    //ui.plainTextEditOutput_DP->setPlainText(decryptedText);

    QString encryptedText_ = ui.plainTextEditInput_DP->toPlainText();
    QString thisKey_ = ui.plainTextEditKeySynch->toPlainText();
    std::string decryptedText_;

    // Декодирование текста из Base64 в бинарный вид
    std::string encryptedText = base64Decode(encryptedText_.toStdString());
    std::string thisKey = base64Decode(thisKey_.toStdString());

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Извлечение IV из зашифрованного текста
    std::string iv(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);
    encryptedText.erase(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()));

    int decryptedTextLen = encryptedText.length() + EVP_MAX_BLOCK_LENGTH;
    unsigned char* decryptedTextBuffer = new unsigned char[decryptedTextLen];

    int actualDecryptedTextLen;

    EVP_DecryptUpdate(ctx, decryptedTextBuffer, &actualDecryptedTextLen, reinterpret_cast<const unsigned char*>(encryptedText.c_str()), encryptedText.length());
    decryptedText_.append(reinterpret_cast<const char*>(decryptedTextBuffer), actualDecryptedTextLen);

    delete[] decryptedTextBuffer;

    EVP_DecryptFinal_ex(ctx, decryptedTextBuffer + actualDecryptedTextLen, &actualDecryptedTextLen);

    decryptedText_.append(reinterpret_cast<const char*>(decryptedTextBuffer), actualDecryptedTextLen);

    EVP_CIPHER_CTX_free(ctx);

    ui.plainTextEditOutput_DP->setPlainText(QString::fromStdString(decryptedText_));
}

void SynchAsynchEncryption::decryptAsynch()
{

}

std::string SynchAsynchEncryption::generateRandomKey()
{
    unsigned char* key;
    int key_length = EVP_CIPHER_key_length(EVP_aes_256_cbc());
    key = new unsigned char[key_length];
    RAND_bytes(key, key_length);
    return std::string(reinterpret_cast<const char*>(key), key_length);
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
