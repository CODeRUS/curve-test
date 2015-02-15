#include "curve25519test.h"

#include "../libcurve25519/curve.h"
#include "../libcurve25519/curve_global.h"

#include "../libaxolotl/ecc/curve.h"
#include "../libaxolotl/ecc/djbec.h"
#include "../libaxolotl/util/byteutil.h"

#include "../libaxolotl/invalidkeyexception.h"

#include <openssl/rand.h>

#include <QByteArray>

#include <QDebug>

Curve25519Test::Curve25519Test()
{
}

void Curve25519Test::testCurve()
{
    qDebug() << "testCurve";

    RAND_poll();

    unsigned char buff1[32];
    memset(buff1, 0, 32);
    RAND_bytes(buff1, 32);

    QByteArray rand1 = QByteArray::fromRawData((const char*)buff1, 32);

    unsigned char buff2[64];
    memset(buff2, 0, 64);
    RAND_bytes(buff2, 64);

    QByteArray rand2 = QByteArray::fromRawData((const char*)buff2, 64);

    QByteArray privateKey = rand1;

    Curve25519::generatePrivateKey(privateKey.data());
    QByteArray publicKey(32, '\0');

    Curve25519::generatePublicKey(privateKey.constData(), publicKey.data());
    QByteArray message = publicKey;

    QByteArray agreement(32, '\0');
    Curve25519::calculateAgreement(privateKey.constData(), publicKey.constData(), agreement.data());

    QByteArray signature(64, '\0');
    Curve25519::calculateSignature((unsigned char*)privateKey.constData(),
                                   (unsigned char*)message.constData(), message.size(),
                                   (unsigned char*)rand2.constData(),
                                   (unsigned char*)signature.data());
    int verified = Curve25519::verifySignature((unsigned char*)publicKey.constData(),
                                               (unsigned char*)message.constData(), message.size(),
                                               (unsigned char*)signature.constData());

    qDebug() << "VERIFIED " << (verified == 0);

    if (verified != 0) {
        qDebug() << "RANDM32  " << rand1.size() << rand1.toHex();
        qDebug() << "RANDM64  " << rand2.size() << rand2.toHex();
        qDebug() << "PRIVATE  " << privateKey.size() << privateKey.toHex();
        qDebug() << "PUBLIC   " << publicKey.size() << publicKey.toHex();
        qDebug() << "MESSAGE  " << message.size() << message.toHex();
        qDebug() << "AGREEMENT" << agreement.size() << agreement.toHex();
        qDebug() << "SIGNATURE" << signature.size() << signature.toHex();
    }
}

void Curve25519Test::simpleTest()
{
}

void Curve25519Test::testAgreement()
{
    qDebug() << "testAgreement";

    try {
        QByteArray alicePublic  = QByteArray::fromHex("051bb75966f2e93a3691dfff942bb2a466a1c08b8d78ca3f4d6df8b8bfa2e4ee28");
        QByteArray alicePrivate = QByteArray::fromHex("c806439dc9d2c476ffed8f2580c0888d58ab406bf7ae3698879021b96bb4bf59");
        QByteArray bobPublic    = QByteArray::fromHex("05653614993d2b15ee9e5fd3d86ce719ef4ec1daae1886a87b3f5fa9565a27a22f");
        QByteArray bobPrivate   = QByteArray::fromHex("b03b34c33a1c44f225b662d2bf4859b8135411fa7b0386d45fb75dc5b91b4466");
        QByteArray shared       = QByteArray::fromHex("325f239328941ced6e673b86ba41017448e99b649a9c3806c1dd7ca4c477e629");

        DjbECPublicKey  alicePublicKey = Curve::decodePoint(alicePublic, 0);
        DjbECPrivateKey alicePrivateKey = Curve::decodePrivatePoint(alicePrivate);

        DjbECPublicKey  bobPublicKey = Curve::decodePoint(bobPublic, 0);
        DjbECPrivateKey bobPrivateKey = Curve::decodePrivatePoint(bobPrivate);

        QByteArray sharedOne = Curve::calculateAgreement(alicePublicKey, bobPrivateKey);
        QByteArray sharedTwo = Curve::calculateAgreement(bobPublicKey, alicePrivateKey);

        bool status1 = (sharedOne == shared);
        bool status2 = (sharedTwo == shared);

        qDebug() << "VERIFIED " << (status1 && status2);

        if (!status1 || !status2) {
            qDebug() << "alicePublicKey: " << alicePublicKey.serialize().toHex();
            qDebug() << "alicePrivateKey:" << alicePrivateKey.serialize().toHex();
            qDebug() << "bobPublicKey:   " << bobPublicKey.serialize().toHex();
            qDebug() << "bobPrivateKey:  " << bobPrivateKey.serialize().toHex();
            qDebug() << "shared   :      " << shared.toHex();
            qDebug() << "sharedOne:      " << sharedOne.toHex();
            qDebug() << "sharedTwo:      " << sharedTwo.toHex();
        }
    }
    catch (InvalidKeyException &e) {
        qWarning() << "InvalidKeyException" << e.errorMessage();
    }
}

void Curve25519Test::testRandomAgreements()
{
    qDebug() << "testRandomAgreements";

    int i;
    for (i = 0; i < 50; i++) {
        ECKeyPair alice = Curve::generateKeyPair();
        ECKeyPair bob   = Curve::generateKeyPair();
        QByteArray sharedAlice = Curve::calculateAgreement(bob.getPublicKey(),   alice.getPrivateKey());
        QByteArray sharedBob   = Curve::calculateAgreement(alice.getPublicKey(), bob.getPrivateKey());

        if (sharedAlice != sharedBob) {
            qDebug() << "FAILED at" << i;
            break;
        }
    }
    if (i == 50) {
        qDebug() << "VERIFIED";
    }
}

void Curve25519Test::testSignature()
{
    qDebug() << "testSignature";

    QByteArray aliceIdentityPrivate = QByteArray::fromHex("c097248412e58bf05df487968205132794178e367637f5818f81e0e6ce73e865");
    QByteArray aliceIdentityPublic  = QByteArray::fromHex("05ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64");
    QByteArray aliceEphemeralPublic = QByteArray::fromHex("05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a");
    QByteArray aliceSignature       = QByteArray::fromHex("5de88ca9a89b4a115da79109c67c9c7464a3e4180274f1cb8c63c2984e286dfbede82deb9dcd9fae0bfbb821569b3d9001bd8130cd11d486cef047bd60b86e88");

    DjbECPrivateKey alicePrivateKey = Curve::decodePrivatePoint(aliceIdentityPrivate);
    DjbECPublicKey  alicePublicKey  = Curve::decodePoint(aliceIdentityPublic, 0);
    DjbECPublicKey  aliceEphemeral  = Curve::decodePoint(aliceEphemeralPublic, 0);

    int res = Curve::verifySignature(alicePublicKey, aliceEphemeral.serialize(), aliceSignature);

    qDebug() << "VERIFIED" << (res == 0);

    if (res != 0) {
        qDebug() << "alicePrivateKey:" << alicePrivateKey.serialize();
        qDebug() << "alicePublicKey: " << alicePublicKey.serialize();
        qDebug() << "aliceEphemeral: " << aliceEphemeral.serialize();
    }
}



















