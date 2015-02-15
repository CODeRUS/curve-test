#include "ratchetingsessiontest.h"

#include <QByteArray>
#include <QDebug>

#include "../libaxolotl/identitykey.h"
#include "../libaxolotl/ecc/curve.h"
#include "../libaxolotl/ecc/djbec.h"
#include "../libaxolotl/ecc/eckeypair.h"
#include "../libaxolotl/ratchet/bobaxolotlparameters.h"
#include "../libaxolotl/ratchet/aliceaxolotlparameters.h"
#include "../libaxolotl/ratchet/ratchetingsession.h"
#include "../libaxolotl/state/sessionstate.h"

RatchetingSessionTest::RatchetingSessionTest()
{
}

void RatchetingSessionTest::testRatchetingSessionAsBob()
{
    qDebug() << "testRatchetingSessionAsBob";

    QByteArray bobPublic            = QByteArray::fromHex("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458");
    QByteArray bobPrivate           = QByteArray::fromHex("a1cab48f7c893fafa9880a28c3b4999d28d6329562d27a4ea4e22e9ff1bdd65a");
    QByteArray bobIdentityPublic    = QByteArray::fromHex("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626");
    QByteArray bobIdentityPrivate   = QByteArray::fromHex("4875cc69ddf8ea0719ec947d61081135868d5fd801f02c0225e516df2156605e");
    QByteArray aliceBasePublic      = QByteArray::fromHex("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950");
    QByteArray aliceEphemeralPublic = QByteArray::fromHex("056c3e0d1f520283efcc55fca5e67075b904007f1881d151af76df18c51d29d34b");
    QByteArray aliceIdentityPublic  = QByteArray::fromHex("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a");
    QByteArray senderChain          = QByteArray::fromHex("d22fd56d3fec819cf4c3d50c56edfb1c280a1b31964537f1d161e1c93148e36b");

    IdentityKey bobIdentityKeyPublic(bobIdentityPublic, 0);
    DjbECPrivateKey bobIdentityKeyPrivate  = Curve::decodePrivatePoint(bobIdentityPrivate);
    IdentityKeyPair bobIdentityKey(bobIdentityKeyPublic, bobIdentityKeyPrivate);
    DjbECPublicKey bobEphemeralPublicKey   = Curve::decodePoint(bobPublic, 0);
    DjbECPrivateKey bobEphemeralPrivateKey = Curve::decodePrivatePoint(bobPrivate);
    ECKeyPair bobEphemeralKey(bobEphemeralPublicKey, bobEphemeralPrivateKey);
    ECKeyPair bobBaseKey = bobEphemeralKey;

    DjbECPublicKey aliceBasePublicKey       = Curve::decodePoint(aliceBasePublic, 0);
    DjbECPublicKey aliceEphemeralPublicKey  = Curve::decodePoint(aliceEphemeralPublic, 0);
    IdentityKey aliceIdentityPublicKey(aliceIdentityPublic, 0);

    BobAxolotlParameters parameters;
    parameters.setOurIdentityKey(bobIdentityKey);
    parameters.setOurSignedPreKey(bobBaseKey);
    parameters.setOurRatchetKey(bobEphemeralKey);
    //parameters.setOurOneTimePreKey(None);
    parameters.setTheirIdentityKey(aliceIdentityPublicKey);
    parameters.setTheirBaseKey(aliceBasePublicKey);

    SessionState session;

    RatchetingSession::initializeSession(&session, 2, parameters);

    IdentityKey  localIdentityKey = session.getLocalIdentityKey();
    IdentityKey remoteIdentityKey = session.getRemoteIdentityKey();
    QByteArray     senderChainKey = session.getSenderChainKey().getKey();

    bool verified = localIdentityKey == bobIdentityKey.getPublicKey()
            && remoteIdentityKey == aliceIdentityPublicKey
            && senderChainKey == senderChain;

    qDebug() << "VERIFIED" << verified;

    if (!verified) {
        qDebug() << "bobIdentityKeyPublic:   " << bobIdentityKeyPublic.serialize().toHex();
        qDebug() << "bobIdentityKeyPrivate:  " << bobIdentityKeyPrivate.serialize().toHex();
        qDebug() << "bobEphemeralPublicKey:  " << bobEphemeralPublicKey.serialize().toHex();
        qDebug() << "bobEphemeralPrivateKey: " << bobEphemeralPrivateKey.serialize().toHex();
        qDebug() << "aliceBasePublicKey:     " << aliceBasePublicKey.serialize().toHex();
        qDebug() << "aliceEphemeralPublicKey:" << aliceEphemeralPublicKey.serialize().toHex();
        qDebug() << "aliceIdentityPublicKey: " << aliceIdentityPublicKey.serialize().toHex();
        qDebug() << "localIdentityKey:       " << localIdentityKey.serialize().toHex();
        qDebug() << "remoteIdentityKey:      " << remoteIdentityKey.serialize().toHex();
        qDebug() << "senderChainKey:         " << senderChainKey.toHex();
    }
}

void RatchetingSessionTest::testRatchetingSessionAsAlice()
{
    qDebug() << "testRatchetingSessionAsAlice";

    QByteArray bobPublic             = QByteArray::fromHex("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458");
    QByteArray bobIdentityPublic     = QByteArray::fromHex("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626");
    QByteArray aliceBasePublic       = QByteArray::fromHex("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950");
    QByteArray aliceBasePrivate      = QByteArray::fromHex("11ae7c64d1e61cd596b76a0db5012673391cae66edbfcf073b4da80516a47449");
    QByteArray aliceEphemeralPublic  = QByteArray::fromHex("056c3e0d1f520283efcc55fca5e67075b904007f1881d151af76df18c51d29d34b");
    QByteArray aliceEphemeralPrivate = QByteArray::fromHex("d1ba38cea91743d33939c33c84986509280161b8b60fc7870c599c1d46201248");
    QByteArray aliceIdentityPublic   = QByteArray::fromHex("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a");
    QByteArray aliceIdentityPrivate  = QByteArray::fromHex("9040f0d4e09cf38f6dc7c13779c908c015a1da4fa78737a080eb0a6f4f5f8f58");
    QByteArray receiverChain         = QByteArray::fromHex("d22fd56d3fec819cf4c3d50c56edfb1c280a1b31964537f1d161e1c93148e36b");

    IdentityKey bobIdentityKey(bobIdentityPublic, 0);
    DjbECPublicKey bobEphemeralPublicKey   = Curve::decodePoint(bobPublic, 0);
    DjbECPublicKey bobBasePublicKey = bobEphemeralPublicKey;

    DjbECPublicKey  aliceBasePublicKey   = Curve::decodePoint(aliceBasePublic, 0);
    DjbECPrivateKey aliceBasePrivateKey  = Curve::decodePrivatePoint(aliceBasePrivate);
    ECKeyPair aliceBaseKey(aliceBasePublicKey, aliceBasePrivateKey);

    DjbECPublicKey  aliceEphemeralPublicKey  = Curve::decodePoint(aliceEphemeralPublic, 0);
    DjbECPrivateKey aliceEphemeralPrivateKey = Curve::decodePrivatePoint(aliceEphemeralPrivate);
    ECKeyPair       aliceEphemeralKey(aliceEphemeralPublicKey, aliceEphemeralPrivateKey);
    IdentityKey     aliceIdentityPublicKey(aliceIdentityPublic, 0);
    DjbECPrivateKey aliceIdentityPrivateKey  = Curve::decodePrivatePoint(aliceIdentityPrivate);
    IdentityKeyPair aliceIdentityKey(aliceIdentityPublicKey, aliceIdentityPrivateKey);

    SessionState session;

    AliceAxolotlParameters parameters;
    parameters.setOurBaseKey(aliceBaseKey);
    parameters.setOurIdentityKey(aliceIdentityKey);
    parameters.setTheirIdentityKey(bobIdentityKey);
    parameters.setTheirSignedPreKey(bobBasePublicKey);
    parameters.setTheirRatchetKey(bobEphemeralPublicKey);

    RatchetingSession::initializeSession(&session, 2, parameters);

    IdentityKey  localIdentityKey = session.getLocalIdentityKey();
    IdentityKey remoteIdentityKey = session.getRemoteIdentityKey();
    QByteArray   receiverChainKey = session.getReceiverChainKey(bobEphemeralPublicKey).getKey();

    bool verified = localIdentityKey == aliceIdentityKey.getPublicKey()
            && remoteIdentityKey == bobIdentityKey
            && receiverChainKey == receiverChain;

    qDebug() << "VERIFIED" << verified;

    if (!verified) {
        qDebug() << "bobIdentityKey:          " << bobIdentityKey.serialize().toHex();
        qDebug() << "bobEphemeralPublicKey:   " << bobEphemeralPublicKey.serialize().toHex();

        qDebug() << "aliceBasePublicKey:      " << aliceBasePublicKey.serialize().toHex();
        qDebug() << "aliceBasePrivateKey:     " << aliceBasePrivateKey.serialize().toHex();

        qDebug() << "aliceEphemeralPublicKey: " << aliceEphemeralPublicKey.serialize().toHex();
        qDebug() << "aliceEphemeralPrivateKey:" << aliceEphemeralPrivateKey.serialize().toHex();
        qDebug() << "aliceIdentityPublicKey:  " << aliceIdentityPublicKey.serialize().toHex();
        qDebug() << "aliceIdentityPrivateKey: " << aliceIdentityPrivateKey.serialize().toHex();
        qDebug() << "localIdentityKey:        " << localIdentityKey.serialize().toHex();
        qDebug() << "remoteIdentityKey:       " << remoteIdentityKey.serialize().toHex();
        qDebug() << "receiverChainKey:        " << receiverChainKey.toHex();
    }
}
