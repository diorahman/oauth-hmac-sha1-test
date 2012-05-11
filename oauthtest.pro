#-------------------------------------------------
#
# Project created by QtCreator 2012-05-11T22:29:59
#
#-------------------------------------------------

QT       += core network

QT       -= gui

TARGET = oauthtest
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


include(oauth/oauth.pri)

SOURCES += main.cpp
