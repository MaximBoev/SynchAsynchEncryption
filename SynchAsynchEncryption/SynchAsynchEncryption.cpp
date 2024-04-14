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
    std::string thisText_S = thisText_QS.toStdString();
    QByteArray thisText_QBA = QByteArray(thisText_S.c_str(), thisText_S.length());
    QByteArray thisKey_QBA = randomBytes();
    synchKey = thisKey_QBA;
    
     // Инициализируем контекст.
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
     
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
    int len_c = len + EVP_MAX_BLOCK_LENGTH;
    int len_f = 0;
    unsigned char* cipher = new unsigned char[len_c];
    
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
    QString encryptedTextHex_QS = QString(thisEncryptText_QBA.toHex());
    QString thisKeyHex_QS = QString(thisKey_QBA.toHex());
    
    ui.plainTextEditOutput_EP->setPlainText(encryptedTextHex_QS);
    ui.plainTextEditKeySynch->setPlainText(thisKeyHex_QS);
    
    EVP_CIPHER_CTX_free(ctx);
    //QString thisText_ = ui.plainTextEditInput_EP->toPlainText();
    //std::string thisText = thisText_.toStdString();
    //std::string thisKey = generateRandomKey();
    //std::string iv;
    //EVP_CIPHER_CTX* ctx;
    //ctx = EVP_CIPHER_CTX_new();
    //EVP_CIPHER_CTX_init(ctx);
    //
    //unsigned char iv_buffer[EVP_MAX_IV_LENGTH];
    //RAND_bytes(iv_buffer, EVP_MAX_IV_LENGTH);
    //iv = std::string(reinterpret_cast<const char*>(iv_buffer), EVP_MAX_IV_LENGTH);
    //iv_ = iv;
    //std::string encrypted_text;
    //
    //EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()));
    //
    //int cipher_text_len = thisText.length() + EVP_MAX_BLOCK_LENGTH;
    //unsigned char* cipher_text = new unsigned char[cipher_text_len];
    //
    //int actual_cipher_text_len;
    //
    //EVP_EncryptUpdate(ctx, cipher_text, &actual_cipher_text_len, reinterpret_cast<const unsigned char*>(thisText.c_str()), thisText.length());
    //encrypted_text.append(reinterpret_cast<const char*>(cipher_text), actual_cipher_text_len);
    //
    //delete[] cipher_text;
    //
    //EVP_CIPHER_CTX_free(ctx);
    //
    //QByteArray encryptedTextByteArray(reinterpret_cast<const char*>(encrypted_text.data()), encrypted_text.length());
    //QByteArray thisKeyByteArray(thisKey.c_str(), thisKey.length());
    //
    //QString encryptedTextHex = QString(encryptedTextByteArray.toHex());
    //QString thisKeyHex = QString(thisKeyByteArray.toHex());
    //
    //ui.plainTextEditOutput_EP->setPlainText(encryptedTextHex);
    //ui.plainTextEditKeySynch->setPlainText(thisKeyHex);
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
    
    QByteArray ivData_QBA = thisEncryptedText_QBA.mid(0, EVP_MAX_IV_LENGTH);
    QByteArray encryptedTextData_QBA = thisEncryptedText_QBA.mid(EVP_MAX_IV_LENGTH);
    
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey_QBA.data())
        , reinterpret_cast<const unsigned char*>(ivData_QBA.data()))) {
        assert(1 != 1);
        success = false;
    }
    
    int len = encryptedTextData_QBA.size();
    int len_f = 0;
    int len_p = len;
    unsigned char* decipher = new unsigned char[len_p + EVP_MAX_BLOCK_LENGTH];
    
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
        QString thisDecryptedText_QS = thisDecryptedText_QBA.toHex();
        ui.plainTextEditOutput_DP->setPlainText(thisDecryptedText_QS);
    }
    //68656c6c6f20776f726c64
    EVP_CIPHER_CTX_free(ctx);
    delete[] decipher;
    
    return;

    //QString encryptedText_ = ui.plainTextEditInput_DP->toPlainText();
    //QString thisKey_ = ui.plainTextEditKeySynch->toPlainText();
    //std::string decryptedText_;
    //
    //std::string encryptedText = hexDecode(encryptedText_.toStdString());
    //std::string thisKey = hexDecode(thisKey_.toStdString());
    //
    //EVP_CIPHER_CTX* ctx;
    //ctx = EVP_CIPHER_CTX_new();
    //EVP_CIPHER_CTX_init(ctx);
    //
    //EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey.c_str()), reinterpret_cast<const unsigned char*>(iv_.c_str()));
    //
    //int decryptedTextLen = 0;
    //unsigned char* decryptedTextBuffer = new unsigned char[encryptedText.length() + EVP_MAX_BLOCK_LENGTH];
    //
    //int actualDecryptedTextLen;
    //
    //EVP_DecryptUpdate(ctx, decryptedTextBuffer, &actualDecryptedTextLen, reinterpret_cast<const unsigned char*>(encryptedText.c_str()), encryptedText.length());
    //decryptedTextLen += actualDecryptedTextLen;
    //
    //EVP_DecryptFinal_ex(ctx, decryptedTextBuffer + decryptedTextLen, &actualDecryptedTextLen);
    //decryptedTextLen += actualDecryptedTextLen;
    //
    //decryptedText_.append(reinterpret_cast<const char*>(decryptedTextBuffer), decryptedTextLen);
    //
    //delete[] decryptedTextBuffer;
    //
    //EVP_CIPHER_CTX_free(ctx);
    //
    //ui.plainTextEditOutput_DP->setPlainText(QString::fromStdString(decryptedText_));
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
