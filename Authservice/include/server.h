#pragma once

#include <QTcpServer>
#include <QTcpSocket>

class Server : public QTcpServer
{
    Q_OBJECT

public:
    Server(QObject* parent = nullptr);
    bool startServer(quint16 port);

protected:
    void incomingConnection(qintptr socketDescriptor) override;

private slots:
    void onReadyRead();
    void onDisconnected();

private:
    void processRequest(QTcpSocket* socket, const QByteArray& data);
    QByteArray generateJwtToken(const QString& userId);
    bool validateJwtToken(const QByteArray& token);
};

