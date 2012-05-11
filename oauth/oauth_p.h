#ifndef OAUTH_P_H
#define OAUTH_P_H

#include <QObject>
#include <QDateTime>
#include <QUrl>
#include <QRegExp>
#include <QStringList>
#include <QSslConfiguration>
#include <qmath.h>

#include "oauth_types.h"

#define DEBUG() qDebug() << __PRETTY_FUNCTION__ << " line: " << __LINE__ << " -> "

class QNetworkAccessManager;
class QNetworkRequest;
class OAuth;

static const QByteArray NONCE_CHARS("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");

class OAuthPrivate : public QObject
{
    Q_OBJECT
    Q_DECLARE_PUBLIC(OAuth)

public:
    enum RequestType { RequestToken, AccessToken, Resource};

    explicit OAuthPrivate(OAuth *parent = 0);
    virtual ~OAuthPrivate(){ delete config;}
    void requestToken(const QString & url);
    void accessToken(const QString & url, const QString & oauthVerifier = "");
    void resource(const QString & url, const QString & method, const ParamsList & params = ParamsList(), const bool & iRaw = false);

private:

    void secureRequest(QNetworkRequest * request, const QString &method = "POST" , const ParamsList & params = ParamsList(), const bool & isRaw = false);
    void signRequest(QNetworkRequest * request, const QString &method = "POST" , const ParamsList & params = ParamsList());

    ParamsList prepareAuthHeaders(const ParamsList & params);
    QString authHeaders(const QString & httpMethod, const QString & strUrl, const ParamsList & params);

    QString hmacsha1(const QString & key, const QString & data);
    QString signatureBase(const QString & method, const QString & url, const QString & params);
    QString signature(const QString & signatureBase);

    QByteArray bodyFromParams(const ParamsList & params){

        if(params.isEmpty()) return QByteArray();

        QString body;

        for(int i = 0; i < params.length(); i++){
            body += params.at(i).first + "=" + params.at(i).second + "&";
        }

        return body.mid(0, body.length() - 1).toAscii();
    }

    QString queryFromParams(const ParamsList & params, bool isQueryIncluded){
        if(params.isEmpty()) return "";

        if(isQueryIncluded)
            return QString("?") + QString(bodyFromParams(params));
        else
            return QString("&") + QString(bodyFromParams(params));
    }

    inline qint64 timestamp(){
        return qFloor(QDateTime::currentMSecsSinceEpoch()/1000.0);
    }

    inline QString encode(const QString & str){
        return QUrl::toPercentEncoding(str);
    }

    inline QString val(const QString & str, int idx = 1){
        return str.split("=").at(idx);
    }

    inline QString key(const QString & str){
        return val(str, 0);
    }

    inline ParamsList parseOAuthReply(const QString & reply){
        ParamsList p;
        QStringList l = reply.split("&");
        for(int i = 0; i < l.length(); i++){
            p.append(Param(key(l.at(i)), (val(l.at(i))).toAscii()));
        }

        return p;
    }

    QString nonce(const short & size){

        QString result;

        QTime t(0, 0, 0);
        qsrand(t.secsTo(QTime::currentTime()));

        for (short i = 0; i < size; i++) {
            result.append(NONCE_CHARS.at(qrand() % NONCE_CHARS.length()));
        }

        return result;
    }

    QString normalizeUrl(const QString & strUrl){
        QUrl url(strUrl);

        QString port = "";

        if(url.port() > 0){
            if((url.scheme() == "http" && url.port() != 80)
                || (url.scheme() == "https" && url.port() != 443)
                    ){
                port += QString(":%1").arg(url.port());
            }
        }

        return url.scheme() + "://" + url.host() + port + url.path();
    }

    inline bool isOAuthParam(const QString & param){
        return (param.indexOf(QRegExp("^oauth_")) > -1);
    }

private slots:
    void secureReply();

public:
    QString consumerKey;
    QString consumerSecret;
    QString oauthToken;
    QString oauthTokenSecret;
    QString callbackUrl;

private:
    QNetworkAccessManager * nam;
    OAuth * const q_ptr;
    QSslConfiguration * config;

};

#endif // OAUTH_P_H

