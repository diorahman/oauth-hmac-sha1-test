#include "oauth.h"
#include "oauth_p.h"

OAuth::OAuth(QObject *parent) :
    QObject(parent), d_ptr(new OAuthPrivate(this))
{
}

OAuth::OAuth(const QString &consumerKey, const QString &consumerSecret, const QString &oauthToken, const QString &oauthTokenSecret, const QString &callbackUrl, QObject *parent):
    QObject(parent), d_ptr(new OAuthPrivate(this))

{
    Q_D(OAuth);
    d->consumerKey = consumerKey;
    d->consumerSecret = consumerSecret;
    d->oauthToken = oauthToken;
    d->oauthTokenSecret = oauthTokenSecret;
    d->callbackUrl = callbackUrl;
}

OAuth::~OAuth()
{
    delete d_ptr;
}

void OAuth::requestToken(const QString & url)
{
    Q_D(OAuth);
    d->requestToken(url);
}

void OAuth::accessToken(const QString &url, const QString & oauthToken, const QString & oauthTokenSecret, const QString & oauthVerifier)
{
    Q_D(OAuth);
    d->oauthToken = oauthToken;
    d->oauthTokenSecret = oauthTokenSecret;
    d->accessToken(url, oauthVerifier);
}

void OAuth::resource(const QString &url, const QString oauthToken, const QString &oauthTokenSecret, const QString &method, const ParamsList &params, const bool & isRaw)
{
    Q_D(OAuth);
    d->oauthToken = oauthToken;
    d->oauthTokenSecret = oauthTokenSecret;
    d->resource(url, method, params, isRaw);
}

void OAuth::resource(const QString &url, const QString &method, const ParamsList &params, const bool & isRaw)
{
    Q_D(OAuth);
    d->resource(url, method, params, isRaw);

}

/*void OAuth::resource(const QString &url, const QString &method, const QString oauthToken, const QString &oauthTokenSecret, const ParamsList &params)
{
    Q_D(OAuth);
    d->oauthToken = oauthToken;
    d->oauthTokenSecret = oauthTokenSecret;
    d->resource(url, method, params);
}

void OAuth::resource(const QString &url, const QString &method, const ParamsList &params)
{
    Q_D(OAuth);
    d->resource(url, method, params);
}
*/
void OAuth::setConsumerKey(const QString &aConsumerKey)
{
    Q_D(OAuth);
    if(aConsumerKey != d->consumerKey){
        d->consumerKey = aConsumerKey;
    }
}

void OAuth::setConsumerSecret(const QString &aConsumerSecret)
{
    Q_D(OAuth);
    if(aConsumerSecret != d->consumerSecret){
        d->consumerSecret = aConsumerSecret;
    }
}

void OAuth::setOauthToken(const QString &anOauthToken)
{
    Q_D(OAuth);
    if(anOauthToken != d->oauthToken){
        d->oauthToken = anOauthToken;
    }
}

void OAuth::setOauthTokenSecret(const QString &anOauthTokenSecret)
{
    Q_D(OAuth);
    if(anOauthTokenSecret != d->oauthTokenSecret){
        d->oauthTokenSecret = anOauthTokenSecret;
    }
}

void OAuth::setCallbackUrl(const QString &aCallbackUrl)
{
    Q_D(OAuth);
    if(aCallbackUrl != d->callbackUrl){
        d->callbackUrl = aCallbackUrl;
    }
}

QString OAuth::consumerKey()
{
    Q_D(OAuth);
    return d->consumerKey;
}

QString OAuth::consumerSecret()
{
    Q_D(OAuth);
    return d->consumerSecret;
}

QString OAuth::oauthToken()
{
    Q_D(OAuth);
    return d->oauthToken;
}

QString OAuth::oauthTokenSecret()
{
    Q_D(OAuth);
    return d->oauthTokenSecret;
}

QString OAuth::callbackUrl()
{
    Q_D(OAuth);
    return d->callbackUrl;
}

