#include <QtCore/QCoreApplication>

#include "oauth.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QString consumerKey("consumerkey");
    QString consumerSecret("consumersecret");

    OAuth * o = new OAuth(
                    consumerKey,
                    consumerSecret,
                    "oauthToken",
                    "oauthTokenSecret",
                    "",
                    qApp);

    o->resource("https://api.twitter.com/1/account/verify_credentials.json", "GET");


    
    return a.exec();
}
