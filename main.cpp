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
                    "222985359-r1JMXBeAJ9CWZwGAWa09lmRCtu9ZYmm5Q9Qb1cY5",
                    "ikVebrB1O4Os6RxpGIvA5ZBF55qPyxPcjB92IbEjvQ",
                    "",
                    qApp);

    //o->resource("https://api.twitter.com/1/account/verify_credentials.json", "GET");


    ParamsList list;

    list.append(Param("status","cumi cumi"));
    list.append(Param("include_entities","1"));

    o->resource("https://api.twitter.com/1/statuses/update.json", "POST", list);
    return a.exec();
}
