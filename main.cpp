#include <QtCore/QCoreApplication>

#include "oauth.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QString consumerKey("W3f50lSJiI00CDVg6UwhxQ");
    QString consumerSecret("CHPWgrNu1wanwvSXax3b7FQarXBgVeZXUFysD4yZKXg");

    OAuth * o = new OAuth(
                    consumerKey,
                    consumerSecret,
                    "222985359-doXx8xsjENAgGsFBBTt9JjHCxuoXNb45Kd1RnGoh",
                    "pjm6uDyALRIXsyN0ZHQo3Rz5R7UzXd932O8Lq20aE",
                    "",
                    qApp);

    o->resource("https://api.twitter.com/1/account/verify_credentials.json", "GET");


    
    return a.exec();
}
