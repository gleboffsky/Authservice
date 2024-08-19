#include "server.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QCryptographicHash>
#include <QDebug>

Server::Server(QObject* parent)
    : QTcpServer(parent)
{
    qDebug() << "Server initialized.";
}

bool Server::startServer(quint16 port)
{
    bool success = listen(QHostAddress::Any, port);
    if (success) {
        qDebug() << "Server listening on port" << port;
    }
    else {
        qCritical() << "Failed to start server on port" << port;
    }
    return success;
}

void Server::incomingConnection(qintptr socketDescriptor)
{
    qDebug() << "Incoming connection request, socket descriptor:" << socketDescriptor;

    QTcpSocket* socket = new QTcpSocket(this);
    if (socket->setSocketDescriptor(socketDescriptor)) {
        connect(socket, &QTcpSocket::readyRead, this, &Server::onReadyRead);
        connect(socket, &QTcpSocket::disconnected, this, &Server::onDisconnected);
        qDebug() << "New connection established with descriptor:" << socketDescriptor;
    }
    else {
        qCritical() << "Failed to set socket descriptor:" << socket->errorString();
        delete socket;
    }
}

void Server::onReadyRead()
{
    qDebug() << "Data received.";
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (socket) {
        QByteArray data = socket->readAll();
        processRequest(socket, data);
        qDebug() << "Received data: " << data;
    }
    else {
        qWarning() << "Failed to cast sender to QTcpSocket.";
    }
}

void Server::onDisconnected()
{
    qDebug() << "Client disconnected.";
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (socket) {
        qDebug() << "Client disconnected:" << socket->socketDescriptor();
        socket->deleteLater();
    }
}

void Server::processRequest(QTcpSocket* socket, const QByteArray& data) {
    QString request = QString::fromUtf8(data);
    QString httpResponse;

    if (request.startsWith("GET")) {
        QString userId = "exampleUser"; 
        QByteArray token = generateJwtToken(userId);
        QString tokenStr = QString(token);
        httpResponse = "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: " + QString::number(tokenStr.size()) + "\r\n\r\n" +
            "<html><body><h1>Your JWT Token:</h1><p>" + tokenStr + "</p></body></html>";
        socket->write(httpResponse.toUtf8());
        socket->flush();
        return;
    }

    QJsonDocument requestDoc = QJsonDocument::fromJson(data);
    QJsonObject requestObj = requestDoc.object();
    QString command = requestObj.value("command").toString();
    qDebug() <<"////" << command << "////";
    if (command == "login") {
        QString userId = requestObj.value("userId").toString();
        QByteArray token = generateJwtToken(userId);
        QJsonObject responseObj;
        responseObj["token"] = QString(token);
        QJsonDocument responseDoc(responseObj);
        QString jsonResponse = responseDoc.toJson(QJsonDocument::Compact);

        httpResponse = "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + QString::number(jsonResponse.size()) + "\r\n\r\n" +
            jsonResponse;
    }
    else if (command == "validate") {
        QByteArray token = requestObj.value("token").toString().toUtf8();
        bool isValid = validateJwtToken(token);

        QJsonObject responseObj;
        responseObj["isValid"] = isValid;

        QJsonDocument responseDoc(responseObj);
        QString jsonResponse = responseDoc.toJson(QJsonDocument::Compact);

        httpResponse = "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + QString::number(jsonResponse.size()) + "\r\n\r\n" +
            jsonResponse;
    }
    else {
        qDebug() << "Unknown command:" << command;
        QJsonObject responseObj;
        responseObj["error"] = "Unknown command";

        QJsonDocument responseDoc(responseObj);
        QString jsonResponse = responseDoc.toJson(QJsonDocument::Compact);

        httpResponse = "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + QString::number(jsonResponse.size()) + "\r\n\r\n" +
            jsonResponse;
    }

    socket->write(httpResponse.toUtf8());
    socket->flush();
}


QByteArray Server::generateJwtToken(const QString& userId)
{
    qDebug() << "Generating JWT token for user:" << userId;
    QJsonObject payload;
    payload["userId"] = userId;
    payload["exp"] = static_cast<qint64>(QDateTime::currentDateTimeUtc().addSecs(3600).toTime_t());

    QJsonDocument doc(payload);
    QByteArray token = doc.toJson(QJsonDocument::Compact);

    QByteArray secretKey = "supersecretkey";

    QByteArray signature = QCryptographicHash::hash(token + secretKey, QCryptographicHash::Sha256);

    return token + "." + signature.toHex();
}

bool Server::validateJwtToken(const QByteArray& token)
{
    qDebug() << "Validating JWT token:" << token;
    QList<QByteArray> parts = token.split('.');
    if (parts.size() != 2) {
        return false;
    }

    QByteArray payload = parts[0];
    QByteArray signature = parts[1];

    QByteArray secretKey = "supersecretkey";
    QByteArray expectedSignature = QCryptographicHash::hash(payload + secretKey, QCryptographicHash::Sha256).toHex();

    if (signature == expectedSignature) {
        QJsonDocument doc = QJsonDocument::fromJson(payload);
        QJsonObject payloadObj = doc.object();

        if (payloadObj.contains("exp")) {
            qint64 exp = payloadObj.value("exp").toDouble();
            if (QDateTime::currentDateTimeUtc().toTime_t() < exp) {
                return true;
            }
        }
    }

    return false;
}
