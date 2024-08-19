# Указываем используемые модули Qt
QT += core network

# Определяем конфигурацию проекта
CONFIG += c++14 console

# Указываем исходные файлы проекта
SOURCES += \
    src/main.cpp \
    src/server.cpp

# Указываем заголовочные файлы проекта
HEADERS += \
    include/server.h

# Указываем, что это консольное приложение
CONFIG += console
