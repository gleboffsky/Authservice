#include <QtCore/QCoreApplication>
#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>
#include "server.h"

int main(int argc, char* argv[])
{
    QCoreApplication a(argc, argv);
    Server server;
    if (!server.startServer(1234)) { 
        qCritical() << "�� ������� ��������� ������!";
        return -1;
    }
    qDebug() << "Server initialized.";
    qDebug() << "Server listening on port 1234.";
    return a.exec();
}
