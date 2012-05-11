#ifndef OAUTH_H
#define OAUTH_H

#include <QObject>
#include <QPair>
#include "oauth_types.h"

class OAuthPrivate;

class OAuth : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QString consumerKey READ consumerKey WRITE setConsumerKey)
    Q_PROPERTY(QString consumerSecret READ consumerSecret WRITE setConsumerSecret)
    Q_PROPERTY(QString oauthToken READ oauthToken WRITE setOauthToken)
    Q_PROPERTY(QString oauthTokenSecret READ oauthTokenSecret WRITE setOauthTokenSecret)
    Q_PROPERTY(QString callbackUrl READ callbackUrl WRITE setCallbackUrl)

    Q_DECLARE_PRIVATE(OAuth)


public:
    explicit OAuth(QObject *parent = 0);
    explicit OAuth(const QString & consumerKey,
                   const QString & consumerSecret,
                   const QString & oauthToken,
                   const QString & oauthTokenSecret,
                   const QString & callbackUrl = "",
                   QObject *parent = 0);

    virtual ~OAuth();

public slots:
    void requestToken(const QString & url);
    void accessToken(const QString & url, const QString & oauthToken, const QString & oauthTokenSecret, const QString & oauthVerifier);
    void resource(const QString & url, const QString oauthToken, const QString & oauthTokenSecret, const QString & method, const ParamsList & params = ParamsList(), const bool & isRaw = false);
    void resource(const QString & url, const QString &method, const ParamsList & params = ParamsList(), const bool & isRaw = false);

signals:
    void accesTokenReceived(const QString & oauthToken, const QString & oauthTokenSecret, const QString & raw);
    void requestTokenReceived(const QString & oauthToken, const QString & oauthTokenSecret, const QString & raw);
    void resourceReceived(const QString & resource);
    void errorOccurred(const QString & errorString);

protected:
    OAuthPrivate * const d_ptr;

public:
    void setConsumerKey(const QString & aConsumerKey);
    void setConsumerSecret(const QString & aConsumerSecret);
    void setOauthToken(const QString & anOauthToken);
    void setOauthTokenSecret(const QString & anOauthTokenSecret);
    void setCallbackUrl(const QString & aCallbackUrl);

    QString consumerKey();
    QString consumerSecret();
    QString oauthToken();
    QString oauthTokenSecret();
    QString callbackUrl();

};

#endif // OAUTH_H

