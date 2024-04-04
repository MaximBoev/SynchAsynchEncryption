#include "SynchAsynchEncryption.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    SynchAsynchEncryption w;
    w.show();
    return a.exec();
    
}
