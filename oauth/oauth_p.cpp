#include "oauth_p.h"
#include "oauth.h"
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QCryptographicHash>
#include <QSslConfiguration>

#include <QDebug>

OAuthPrivate::OAuthPrivate(OAuth * publicAPI) : q_ptr(publicAPI)
{
    nam = new QNetworkAccessManager(this);
    config = new QSslConfiguration(QSslConfiguration::defaultConfiguration());

    QList<QSslCertificate> cert = config->caCertificates();
    cert.append(QSslCertificate::fromPath(":/cacert.pem"));
    config->setCaCertificates(cert);

}

void OAuthPrivate::requestToken(const QString & url)
{
    QUrl endpoint(url);
    QNetworkRequest * request = new QNetworkRequest(endpoint);
    request->setAttribute(QNetworkRequest::User, OAuthPrivate::RequestToken);
    secureRequest(request, "POST", ParamsList());
}

void OAuthPrivate::accessToken(const QString &url, const QString &oauthVerifier)
{
    QUrl endpoint(url);
    ParamsList oauthParams;

    if(!oauthVerifier.isEmpty())
        oauthParams.append(Param("oauth_verifier", oauthVerifier.toAscii()));

    QNetworkRequest * request = new QNetworkRequest(endpoint);
    request->setAttribute(QNetworkRequest::User, OAuthPrivate::AccessToken);
    secureRequest(request, "POST", oauthParams);
}

void OAuthPrivate::resource(const QString &url, const QString &method, const ParamsList &params, const bool &isRaw)
{
    QUrl endpoint(url);

    QNetworkRequest * request = new QNetworkRequest(endpoint);
    request->setAttribute(QNetworkRequest::User, OAuthPrivate::Resource);
    secureRequest(request, method.toUpper(), params, isRaw);
}

void OAuthPrivate::secureReply()
{
    QNetworkReply * reply = qobject_cast<QNetworkReply * >(sender());

    Q_Q(OAuth);

    QString data = reply->readAll();

    DEBUG() << data;
    DEBUG() << reply->errorString();

    if(reply->error() == QNetworkReply::NoError){

        switch(reply->request().attribute(QNetworkRequest::User).toInt()){
            case OAuthPrivate::RequestToken: {ParamsList p = parseOAuthReply(data); emit q->requestTokenReceived(p.at(0).second, p.at(1).second, data);} break;
            case OAuthPrivate::AccessToken : {ParamsList p = parseOAuthReply(data); emit q->accesTokenReceived(p.at(0).second, p.at(1).second, data);} break;
            default: emit q->resourceReceived(data); break;
        }

    }else{
        emit q->errorOccurred(reply->errorString());
    }
}

void OAuthPrivate::secureRequest(QNetworkRequest * request, const QString &method, const ParamsList & params, const bool &isRaw)
{
    signRequest(request, method.toUpper(), params);

    QNetworkReply * reply = 0;

    if(method.toUpper() == "POST" || method.toUpper() == "PUT"){

        QByteArray body;

        if(!isRaw){
            body = bodyFromParams(params);
            request->setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        }else{
            body = params.at(0).second;
        }

        request->setHeader(QNetworkRequest::ContentLengthHeader, body.length());

        if(method.toUpper() == "POST")
            reply = nam->post(* request, body);
        else
            reply = nam->put(* request, body);

    }else{

        QUrl queryUrl(request->url().toString() + queryFromParams(params, request->url().toString().contains("?")));
        request->setUrl(queryUrl);

        if(method.toUpper() == "GET"){
            DEBUG() << "GET";
            reply = nam->get(* request);

        }
        else
            reply = nam->deleteResource(* request);
    }

    if(reply){
        reply->setSslConfiguration(* config);
        connect(reply, SIGNAL(finished()), this, SLOT(secureReply()));
    }

    delete request;
}

void OAuthPrivate::signRequest(QNetworkRequest * request, const QString &method, const ParamsList & params)
{
    request->setRawHeader(QString("Authorization").toAscii(), authHeaders(method, request->url().toString(), prepareAuthHeaders(params)).toAscii());
    request->setRawHeader(QString("Host").toAscii(), request->url().host().toAscii());
    request->setRawHeader(QString("Connection").toAscii(), QString("close").toAscii());

    DEBUG() << authHeaders(method, request->url().toString(), prepareAuthHeaders(params)).toAscii();
}

ParamsList OAuthPrivate::prepareAuthHeaders(const ParamsList &params)
{
    ParamsList oauthParams;

    oauthParams.append(Param("oauth_consumer_key", consumerKey.toAscii()));
    oauthParams.append(Param("oauth_nonce", nonce(32).toAscii()));
    oauthParams.append(Param("oauth_signature_method", "HMAC-SHA1"));
    oauthParams.append(Param("oauth_timestamp", (QString("%1").arg(timestamp())).toAscii()));

    if(!oauthToken.isEmpty()){
        oauthParams.append(Param("oauth_token", oauthToken.toAscii()));
    }

    oauthParams.append(Param("oauth_version", "1.0"));

    for(int i = 0; i < params.length(); i++){
        oauthParams.append(params.at(i));
    }

    // sort
    QMap<QString, Param> sorted;

    for(int j = 0; j < oauthParams.length(); j++){
        sorted.insert(oauthParams.at(j).first, oauthParams.at(j));
    }

    return sorted.values();
}

QString OAuthPrivate::authHeaders(const QString & httpMethod, const QString & strUrl, const ParamsList & oauthParams)
{
    QString params;
    QString url = strUrl;
    QString method = httpMethod;
    QString authHeader = "OAuth ";

    for(int i = 0; i < oauthParams.length(); i++){
        params += encode(oauthParams.at(i).first) + "=" + encode(oauthParams.at(i).second) + "&";

        if(isOAuthParam(oauthParams.at(i).first))
            authHeader += encode(oauthParams.at(i).first) + "=\"" + encode(oauthParams.at(i).second) + "\",";
    }

    params = params.mid(0, params.length() - 1);

    DEBUG() << params;

    authHeader += QString("oauth_signature=\"%1\"").arg(encode(signature(signatureBase(method, url, params))));

    return authHeader;
}

QString OAuthPrivate::signatureBase(const QString & method, const QString & url, const QString & params)
{
    QString u = encode(normalizeUrl(url));
    QString p = encode(params);
    return method.toUpper() + "&" + u + "&" + p;
}

QString OAuthPrivate::signature(const QString & signatureBase){
    QString ts = encode(oauthTokenSecret);
    QString key= consumerSecret + "&" + ts; // empty if token secret empty

    return hmacsha1(key, signatureBase);
}

QString OAuthPrivate::hmacsha1(const QString & key, const QString & data){

    QByteArray ipad;
    QByteArray opad;
    QByteArray ctx;
    QByteArray sha1;
    QByteArray k;

    k = key.toAscii();

    int keyLen = key.size();

    if(keyLen > 64){

        QByteArray tempKey;
        tempKey.append(key);
        k = QCryptographicHash::hash(tempKey, QCryptographicHash::Sha1);

        keyLen = 20;
    }

    ipad.fill( 0, 64);
    opad.fill(0, 64);

    ipad.replace(0, keyLen, k);
    opad.replace(0, keyLen, k);

    for (int i=0; i<64; i++)
    {
        ipad[i] = ipad[i] ^ 0x36;
        opad[i] = opad[i] ^ 0x5c;
    }

    ctx.append(ipad,64);
    ctx.append(data);

    sha1 = QCryptographicHash::hash(ctx, QCryptographicHash::Sha1);

    ctx.clear();
    ctx.append(opad,64);
    ctx.append(sha1);

    sha1.clear();

    sha1 = QCryptographicHash::hash(ctx, QCryptographicHash::Sha1);

    return sha1.toBase64();
}


