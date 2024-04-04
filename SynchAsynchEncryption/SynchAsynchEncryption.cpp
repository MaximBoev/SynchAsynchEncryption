#include "SynchAsynchEncryption.h"
#include <openssl/aes.h>
SynchAsynchEncryption::SynchAsynchEncryption(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    
}

SynchAsynchEncryption::~SynchAsynchEncryption()
{}
