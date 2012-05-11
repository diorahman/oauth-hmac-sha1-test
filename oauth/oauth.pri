VPATH += $$PWD
INCLUDEPATH += $$PWD

QT += network

HEADERS += \
    oauth/oauth.h \
    oauth/oauth_p.h \
    oauth/oauth_types.h

SOURCES += \
    oauth/oauth.cpp \
    oauth/oauth_p.cpp

RESOURCES += \
    oauth/cacert.qrc
