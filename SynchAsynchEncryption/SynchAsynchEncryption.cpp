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
#include "base64.h"

#define PRIVATE_KEY_BITS 256
#define PADDING RSA_PKCS1_PADDING
#define DEBUG 1

using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using BIO_MEM_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using BIO_MEM_BUF_ptr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

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

void SynchAsynchEncryption::GenKey(std::string& str_public_key, std::string& str_private_key) {
    int rc;

    RSA_ptr rsa(RSA_new(), ::RSA_free);  // openssl rsa pointer
    BIGNUM_ptr bn(BN_new(), ::BN_free);  // bignum

    int bits = PRIVATE_KEY_BITS;
    unsigned long e = RSA_F4;

    rc = BN_set_word(bn.get(), e);
    assert(rc == 1);

    // Generate RSA key
    rc = RSA_generate_key_ex(rsa.get(), bits, bn.get(), NULL);
    assert(rc == 1);

    // Convert RSA to Private Key
    EVP_KEY_ptr public_key(EVP_PKEY_new(), ::EVP_PKEY_free);
    rc = EVP_PKEY_set1_RSA(public_key.get(), rsa.get());
    assert(rc == 1);

    // Create 2 in-memory BIO for public key and private key
    BIO_MEM_ptr public_key_bio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_MEM_ptr private_key_bio(BIO_new(BIO_s_mem()), ::BIO_free);
    // Write Public Key in Traditional PEM
    rc = PEM_write_bio_PUBKEY(public_key_bio.get(), public_key.get());
    assert(rc == 1);

    // Write Private Key in Traditional PEM
    rc = PEM_write_bio_RSAPrivateKey(private_key_bio.get(), rsa.get(), NULL, NULL, 0, NULL, NULL);
    assert(rc == 1);

    size_t pkey_length = BIO_pending(public_key_bio.get());
    size_t key_length = BIO_pending(private_key_bio.get());

    std::unique_ptr<char> pkey_buff((char*)malloc(pkey_length + 1));
    std::unique_ptr<char> key_buff((char*)malloc(key_length + 1));

    BIO_read(public_key_bio.get(), pkey_buff.get(), pkey_length);
    BIO_read(private_key_bio.get(), key_buff.get(), key_length);

    // NULL Terminator
    pkey_buff.get()[pkey_length] = '\0';
    key_buff.get()[key_length] = '\0';

    str_public_key.assign(pkey_buff.get(), pkey_length);
    str_private_key.assign(key_buff.get(), key_length);

#if DEBUG
    std::cout << "Public key buffer length: " << pkey_length << std::endl;
    std::cout << "Private key buffer length: " << key_length << std::endl;
#endif

}

bool SynchAsynchEncryption::Encrypt(const std::string rsa_public_key, const std::string source,
    std::string& dest) {
    /*
     * @Param:
     * 		rsa_public_key: Traditional PEM Public Key
     * 		source: std::string need to encrypted
     * @Output:
     * 		dest: Encrypted std::string
     * */
    size_t rsa_public_key_len = rsa_public_key.size()
        * sizeof(std::string::value_type);
    size_t msg_size = source.size() * sizeof(std::string::value_type);

    // LOAD PUBLIC KEY FROMS STRING USING OpenSSL's API
    BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free); // I/O abstraction
    // BIO_new_mem_buf((void*) rsa_public_key.c_str(), -1)
    BIO_write(bio.get(), rsa_public_key.c_str(), rsa_public_key_len);
    BIO_set_flags(bio.get(), BIO_FLAGS_BASE64_NO_NL);
    // Read public key
    RSA_ptr _public_key(PEM_read_bio_RSA_PUBKEY(bio.get(), NULL, 0, NULL),
        ::RSA_free);
    if (!_public_key.get()) {
        printf(
            "ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n",
            ERR_error_string(ERR_get_error(), NULL)
        );
        return false;
    }
    int rsa_len = RSA_size(_public_key.get());

    std::unique_ptr<unsigned char> encrypted((unsigned char*)malloc(rsa_len));
    size_t encrypted_data_len = RSA_public_encrypt(msg_size,
        (const unsigned char*)source.c_str(), encrypted.get(),
        _public_key.get(), PADDING);
    if (encrypted_data_len == -1) {
        printf(
            "ERROR: RSA_public_encrypt: %s\n",
            ERR_error_string(ERR_get_error(), NULL)
        );
        return false;
    }

    // To base 64
    int ascii_base64_encrypted_len;
    std::unique_ptr<char> ascii_base64_encrypted(
        base64(encrypted.get(), encrypted_data_len,
            &ascii_base64_encrypted_len));

    dest.assign(ascii_base64_encrypted.get(), ascii_base64_encrypted_len);

    return true;
}

bool SynchAsynchEncryption::Decrypt(const std::string private_key, const std::string source,
    std::string& dest) {
    // Code ngu người những vẫn chạy, must be magic
    int bin_encrypted_len;
    std::unique_ptr<unsigned char> bin_encrypted(
        unbase64(source.c_str(), source.length(), &bin_encrypted_len));

    // LOAD PRIVATE KEY FROM STRING USING OpenSSL API
    BIO_MEM_ptr bio(BIO_new_mem_buf((void*)private_key.c_str(), -1),
        ::BIO_free);
    RSA_ptr _private_key(PEM_read_bio_RSAPrivateKey(bio.get(), NULL, 0, NULL),
        ::RSA_free);

    if (!_private_key.get()) {
        printf(
            "ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    size_t rsa_len = RSA_size(_private_key.get());
    std::unique_ptr<unsigned char> bin_decrypted(
        (unsigned char*)malloc(rsa_len));

    size_t decrypted_data_len = RSA_private_decrypt(rsa_len,
        bin_encrypted.get(), bin_decrypted.get(), _private_key.get(),
        PADDING);
    if (decrypted_data_len == -1) {
        printf("ERROR: RSA_private_decrypt: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    dest.assign(reinterpret_cast<char*>(bin_decrypted.get()), decrypted_data_len);

    return true;
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
   
   QByteArray encryptedTextByteArray(reinterpret_cast<const char*>(encrypted_text.data()), encrypted_text.length());
   QByteArray thisKeyByteArray(thisKey.c_str(), thisKey.length());
   
   QString encryptedTextHex = QString(encryptedTextByteArray.toHex());
   QString thisKeyHex = QString(thisKeyByteArray.toHex());
   
   ui.plainTextEditOutput_EP->setPlainText(encryptedTextHex);
   ui.plainTextEditKeySynch->setPlainText(thisKeyHex);
}

void SynchAsynchEncryption::encryptAsynch()
{
    QString thisText_ = ui.plainTextEditInput_EP->toPlainText();
    std::string thisText = thisText_.toStdString();
    
    GenKey(publicKey, privateKey);
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
    QString encryptedText_ = ui.plainTextEditInput_DP->toPlainText();
    QString thisKey_ = ui.plainTextEditKeySynch->toPlainText();
    std::string decryptedText_;
    
    std::string encryptedText = hexDecode(encryptedText_.toStdString());
    std::string thisKey = hexDecode(thisKey_.toStdString());
    
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    
    std::string iv(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);
    encryptedText.erase(encryptedText.begin(), encryptedText.begin() + EVP_MAX_IV_LENGTH);
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(thisKey.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()));
    
    int decryptedTextLen = 0;
    unsigned char* decryptedTextBuffer = new unsigned char[encryptedText.length() + EVP_MAX_BLOCK_LENGTH];
    
    int actualDecryptedTextLen;
    
    EVP_DecryptUpdate(ctx, decryptedTextBuffer, &actualDecryptedTextLen, reinterpret_cast<const unsigned char*>(encryptedText.c_str()), encryptedText.length());
    decryptedTextLen += actualDecryptedTextLen;
    
    EVP_DecryptFinal_ex(ctx, decryptedTextBuffer + decryptedTextLen, &actualDecryptedTextLen);
    decryptedTextLen += actualDecryptedTextLen;
    
    decryptedText_.append(reinterpret_cast<const char*>(decryptedTextBuffer), decryptedTextLen);
    
    delete[] decryptedTextBuffer;
    
    EVP_CIPHER_CTX_free(ctx);
    
    ui.plainTextEditOutput_DP->setPlainText(QString::fromStdString(decryptedText_));
}

void SynchAsynchEncryption::decryptAsynch()
{

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
