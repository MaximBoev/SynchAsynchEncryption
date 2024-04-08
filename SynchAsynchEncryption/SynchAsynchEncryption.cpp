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
   //
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

    unsigned char* encrypted_text = new unsigned char[thisText.length() + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];

    int ciphertext_len = encrypt_(reinterpret_cast<unsigned char*>(thisText.data()), thisText.length(), NULL, 0,
        reinterpret_cast<unsigned char*>(thisKey.data()), iv_buffer,
        encrypted_text, tag);

    QByteArray encryptedTextByteArray(reinterpret_cast<const char*>(encrypted_text), ciphertext_len);
    QByteArray tagByteArray(reinterpret_cast<const char*>(tag), 16);

    QString encryptedTextHex = QString(encryptedTextByteArray.toHex());
    QString tagHex = QString(tagByteArray.toHex());

    ui.plainTextEditOutput_EP->setPlainText(encryptedTextHex);
    ui.plainTextEditKeySynch->setPlainText(tagHex);

    delete[] encrypted_text;

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
    //std::string encryptedText = hexDecode(encryptedText_.toStdString());
    //std::string thisKey = hexDecode(thisKey_.toStdString());
    //
    //EVP_CIPHER_CTX* ctx;
    //ctx = EVP_CIPHER_CTX_new();
    //EVP_CIPHER_CTX_init(ctx);
    //
    //std::string iv(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);
    //encryptedText.erase(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);
    //
    //EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()));
    //
    //int decryptedTextLen = 0;
    //unsigned char* decryptedTextBuffer = new unsigned char[encryptedText.length() + EVP_MAX_BLOCK_LENGTH]; // Буфер, достаточный для всех данных
    //
    //int actualDecryptedTextLen;
    //
    //// Дешифрование
    //EVP_DecryptUpdate(ctx, decryptedTextBuffer, &actualDecryptedTextLen, reinterpret_cast<const unsigned char*>(encryptedText.c_str()), encryptedText.length());
    //decryptedTextLen += actualDecryptedTextLen;
    //
    //// Завершение дешифрования
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

    QString encryptedText_ = ui.plainTextEditInput_DP->toPlainText();
    QString tagHex_ = ui.plainTextEditKeySynch->toPlainText();

    std::string encryptedText = hexDecode(encryptedText_.toStdString());
    std::string tag = hexDecode(tagHex_.toStdString());

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    std::string iv(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);
    encryptedText.erase(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);

    int decryptedtext_len = encryptedText.length();
    unsigned char* decrypted_text = new unsigned char[decryptedtext_len]; // Выделение памяти для дешифрованного текста

    decryptedtext_len = decrypt_(reinterpret_cast<unsigned char*>(encryptedText.data()), encryptedText.length(), nullptr, 0,
        reinterpret_cast<unsigned char*>(tag.data()), nullptr, reinterpret_cast<unsigned char*>(iv.data()),
        decrypted_text);


    if (decryptedtext_len < 0)
    {
        // Дешифрование не удалось
        // Можно обработать эту ситуацию по своему усмотрению
    }
    else
    {
        // Дешифрование успешно завершено
        // decrypted_text содержит дешифрованный текст

        // Конвертируем дешифрованный текст в QString и отображаем его
        QString decryptedText = QString::fromUtf8(reinterpret_cast<const char*>(decrypted_text), decryptedtext_len);
        ui.plainTextEditOutput_DP->setPlainText(decryptedText);
    }

    EVP_CIPHER_CTX_free(ctx);
    delete[] decrypted_text; // Освобождение выделенной памяти


}

void SynchAsynchEncryption::decryptAsynch()
{

}

int SynchAsynchEncryption::encrypt_(unsigned char* plaintext, int plaintext_len, unsigned char* aad, int aad_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx = NULL;
    int len = 0, ciphertext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    if (aad && aad_len > 0)
    {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    if (plaintext)
    {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int SynchAsynchEncryption::decrypt_(unsigned char* ciphertext, int ciphertext_len, unsigned char* aad,
    int aad_len, unsigned char* tag, unsigned char* key, unsigned char* iv,
    unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /* Provide any AAD data. This can be called zero or more times as required */
    if (aad && aad_len > 0)
    {
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (ciphertext)
    {
        if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors(); // fucking errrrror!!!!!!!!!!!!!

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}

void SynchAsynchEncryption::handleErrors(void)
{
    unsigned long errCode;

    qDebug() << "An error occurred";
    while (errCode = ERR_get_error())
    {
        char* err = ERR_error_string(errCode, NULL);
        qDebug() << err;
    }
    abort();
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
