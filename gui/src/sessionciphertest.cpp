#include "sessionciphertest.h"

#include "../libaxolotl/ecc/curve.h"
#include "../libaxolotl/ecc/djbec.h"
#include "../libaxolotl/ecc/eckeypair.h"
#include "../libaxolotl/ratchet/aliceaxolotlparameters.h"
#include "../libaxolotl/ratchet/bobaxolotlparameters.h"
#include "../libaxolotl/ratchet/ratchetingsession.h"
#include "../libaxolotl/sessioncipher.h"
#include "../libaxolotl/protocol/whispermessage.h"

#include "inmemoryaxolotlstore.h"

#include <QByteArray>
#include <QList>
#include <QSharedPointer>
#include <QDateTime>
#include <QDebug>

#include <openssl/aes.h>

SessionCipherTest::SessionCipherTest()
{
}

void SessionCipherTest::testBasicSessionV2()
{
    qDebug() << "testBasicSessionV2";

    SessionRecord *aliceSessionRecord = new SessionRecord();
    SessionRecord *bobSessionRecord   = new SessionRecord();

    initializeSessionsV2(aliceSessionRecord->getSessionState(), bobSessionRecord->getSessionState());
    runInteraction(aliceSessionRecord, bobSessionRecord);
}

void SessionCipherTest::testBasicSessionV3()
{
    qDebug() << "testBasicSessionV3";

    SessionRecord *aliceSessionRecord = new SessionRecord();
    SessionRecord *bobSessionRecord   = new SessionRecord();

    initializeSessionsV3(aliceSessionRecord->getSessionState(), bobSessionRecord->getSessionState());
    runInteraction(aliceSessionRecord, bobSessionRecord);
}

void SessionCipherTest::runInteraction(SessionRecord *aliceSessionRecord, SessionRecord *bobSessionRecord)
{
    QSharedPointer<AxolotlStore> aliceStore(new InMemoryAxolotlStore());
    QSharedPointer<AxolotlStore> bobStore(new InMemoryAxolotlStore());

    aliceStore->storeSession(2, 1, aliceSessionRecord);
    bobStore->storeSession(3, 1, bobSessionRecord);

    SessionCipher     aliceCipher(aliceStore, 2, 1);
    SessionCipher     bobCipher(bobStore, 3, 1);

    bool test0 = true;
    for (int i = 0; i < 30; i++) {
        QByteArray        alicePlaintext("This is a plaintext message.");
        QSharedPointer<CiphertextMessage> message = aliceCipher.encrypt(alicePlaintext);
        QSharedPointer<WhisperMessage> whisperBob(new WhisperMessage(message->serialize()));
        QByteArray        bobPlaintext   = bobCipher.decrypt(whisperBob);
        if (bobPlaintext != alicePlaintext) {
            qWarning() << "FAILED AT" << i << whisperBob->getBody().toHex();
            qWarning() << "SOURCETEXT:" << alicePlaintext.toHex();
            qWarning() << "PLAINTEXT:" << bobPlaintext.toHex();
            test0 = false;
        }
        message.clear();
        whisperBob.clear();
    }

    qDebug() << "TEST0" << (test0 ? "PASSED" : "FAILED");

    QByteArray        alicePlaintext("This is a plaintext message.");
    QSharedPointer<CiphertextMessage> message = aliceCipher.encrypt(alicePlaintext);
    QSharedPointer<WhisperMessage> whisperBob(new WhisperMessage(message->serialize()));
    QByteArray        bobPlaintext   = bobCipher.decrypt(whisperBob);

    bool passed1 = alicePlaintext == bobPlaintext;
    qDebug() << "PASSED 1" << passed1;

    if (!passed1) {
        qDebug() << "bobPlaintext" << bobPlaintext.toHex();
    }

    QByteArray        bobReply("This is a message from Bob.");
    QSharedPointer<CiphertextMessage> reply = bobCipher.encrypt(bobReply);
    QSharedPointer<WhisperMessage> whisperAlice(new WhisperMessage(reply->serialize()));
    QByteArray        receivedReply = aliceCipher.decrypt(whisperAlice);

    bool passed2 = bobReply == receivedReply;
    qDebug() << "PASSED 2" << passed2;

    if (!passed2) {
        qDebug() << "receivedReply" << receivedReply.toHex();
    }

    QList< QSharedPointer<CiphertextMessage> > aliceCiphertextMessages;
    QList<QByteArray> alicePlaintextMessages;

    for (int i = 0; i < 50; i++) {
        QByteArray msg = QString("test message no %1").arg(i).toUtf8();
        alicePlaintextMessages.append(msg);
        aliceCiphertextMessages.append(aliceCipher.encrypt(msg));
    }

    //long seed = QDateTime::currentMSecsSinceEpoch();

    // X Collections.shuffle(aliceCiphertextMessages, new Random(seed));
    // X Collections.shuffle(alicePlaintextMessages, new Random(seed));

    bool test3 = true;
    for (int i = 0; i < aliceCiphertextMessages.size() / 2; i++) {
        QSharedPointer<WhisperMessage> decryptMessage(new WhisperMessage(aliceCiphertextMessages[i]->serialize()));
        QByteArray receivedPlaintext = bobCipher.decrypt(decryptMessage);

        bool passed3 = receivedPlaintext == alicePlaintextMessages[i];
        //qDebug() << "PASSED 3" << passed3;

        if (!passed3) {
            qDebug() << QString("receivedPlaintext[%1]     ").arg(i) << receivedPlaintext.toHex();
            qDebug() << QString("alicePlaintextMessages[%1]").arg(i) << alicePlaintextMessages[i].toHex();
            test3 = false;
        }
    }
    qDebug() << "TEST3" << (test3 ? "PASSED" : "FAILED");

    QList< QSharedPointer<CiphertextMessage> > bobCiphertextMessages;
    QList<QByteArray> bobPlaintextMessages;

    for (int i = 0; i < 20; i++) {
        QByteArray msg = QString("test message no %1").arg(i).toUtf8();
        bobPlaintextMessages.append(msg);
        bobCiphertextMessages.append(bobCipher.encrypt(msg));
    }

    //seed = QDateTime::currentMSecsSinceEpoch();

    // X Collections.shuffle(bobCiphertextMessages, new Random(seed));
    // X Collections.shuffle(bobPlaintextMessages, new Random(seed));

    bool test4 = true;
    for (int i = 0; i < bobCiphertextMessages.size() / 2; i++) {
        QSharedPointer<WhisperMessage> decryptMessage(new WhisperMessage(bobCiphertextMessages[i]->serialize()));
        QByteArray receivedPlaintext = aliceCipher.decrypt(decryptMessage);

        bool passed4 = receivedPlaintext == bobPlaintextMessages[i];
        //qDebug() << "PASSED 4" << passed4;

        if (!passed4) {
            qDebug() << QString("receivedPlaintext[%1]   ").arg(i) << receivedPlaintext.toHex();
            qDebug() << QString("bobPlaintextMessages[%1]").arg(i) << bobPlaintextMessages[i].toHex();
            test4 = false;
        }
    }
    qDebug() << "TEST4" << (test4 ? "PASSED" : "FAILED");

    bool test5 = true;
    for (int i = aliceCiphertextMessages.size() / 2; i < aliceCiphertextMessages.size(); i++) {
        QSharedPointer<WhisperMessage> decryptMessage(new WhisperMessage(aliceCiphertextMessages[i]->serialize()));
        QByteArray receivedPlaintext = bobCipher.decrypt(decryptMessage);

        bool passed5 = receivedPlaintext == alicePlaintextMessages[i];
        //qDebug() << "PASSED 5" << passed5;

        if (!passed5) {
            qDebug() << QString("receivedPlaintext[%1]     ").arg(i) << receivedPlaintext.toHex();
            qDebug() << QString("alicePlaintextMessages[%1]").arg(i) << alicePlaintextMessages[i].toHex();
            test5 = true;
        }
    }
    qDebug() << "TEST5" << (test5 ? "PASSED" : "FAILED");

    bool test6 = true;
    for (int i = bobCiphertextMessages.size() / 2; i < bobCiphertextMessages.size(); i++) {
        QSharedPointer<WhisperMessage> decryptMessage(new WhisperMessage(bobCiphertextMessages[i]->serialize()));
        QByteArray receivedPlaintext = aliceCipher.decrypt(decryptMessage);

        bool passed6 = receivedPlaintext == bobPlaintextMessages[i];
        //qDebug() << "PASSED 6" << passed6;

        if (!passed6) {
            qDebug() << QString("receivedPlaintext[%1]   ").arg(i) << receivedPlaintext.toHex();
            qDebug() << QString("bobPlaintextMessages[%1]").arg(i) << bobPlaintextMessages[i].toHex();
            test6 = false;
        }
    }
    qDebug() << "TEST6" << (test6 ? "PASSED" : "FAILED");
}

void SessionCipherTest::initializeSessionsV2(SessionState *aliceSessionState, SessionState *bobSessionState)
{
    ECKeyPair       aliceIdentityKeyPair = Curve::generateKeyPair();
    IdentityKeyPair aliceIdentityKey(IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                     aliceIdentityKeyPair.getPrivateKey());
    ECKeyPair       aliceBaseKey         = Curve::generateKeyPair();
    ECKeyPair       aliceEphemeralKey    = Curve::generateKeyPair();

    ECKeyPair       bobIdentityKeyPair   = Curve::generateKeyPair();
    IdentityKeyPair bobIdentityKey(IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                   bobIdentityKeyPair.getPrivateKey());
    ECKeyPair       bobBaseKey           = Curve::generateKeyPair();
    ECKeyPair       bobEphemeralKey      = bobBaseKey;

    AliceAxolotlParameters aliceParameters;
    aliceParameters.setOurIdentityKey(aliceIdentityKey);
    aliceParameters.setOurBaseKey(aliceBaseKey);
    aliceParameters.setTheirIdentityKey(bobIdentityKey.getPublicKey());
    aliceParameters.setTheirSignedPreKey(bobEphemeralKey.getPublicKey());
    aliceParameters.setTheirRatchetKey(bobEphemeralKey.getPublicKey());

    BobAxolotlParameters bobParameters;
    bobParameters.setOurIdentityKey(bobIdentityKey);
    bobParameters.setOurRatchetKey(bobEphemeralKey);
    bobParameters.setOurSignedPreKey(bobBaseKey);
    bobParameters.setTheirBaseKey(aliceBaseKey.getPublicKey());
    bobParameters.setTheirIdentityKey(aliceIdentityKey.getPublicKey());

    RatchetingSession::initializeSession(aliceSessionState, 2, aliceParameters);
    RatchetingSession::initializeSession(bobSessionState, 2, bobParameters);
}

void SessionCipherTest::initializeSessionsV3(SessionState *aliceSessionState, SessionState *bobSessionState)
{
    ECKeyPair       aliceIdentityKeyPair = Curve::generateKeyPair();
    IdentityKeyPair aliceIdentityKey(IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                     aliceIdentityKeyPair.getPrivateKey());
    ECKeyPair       aliceBaseKey         = Curve::generateKeyPair();
    ECKeyPair       aliceEphemeralKey    = Curve::generateKeyPair();

    ECKeyPair       alicePreKey          = aliceBaseKey;

    ECKeyPair       bobIdentityKeyPair   = Curve::generateKeyPair();
    IdentityKeyPair bobIdentityKey(IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                   bobIdentityKeyPair.getPrivateKey());
    ECKeyPair       bobBaseKey           = Curve::generateKeyPair();
    ECKeyPair       bobEphemeralKey      = bobBaseKey;

    ECKeyPair       bobPreKey            = Curve::generateKeyPair();

    AliceAxolotlParameters aliceParameters;
    aliceParameters.setOurBaseKey(aliceBaseKey);
    aliceParameters.setOurIdentityKey(aliceIdentityKey);
    aliceParameters.setTheirRatchetKey(bobEphemeralKey.getPublicKey());
    aliceParameters.setTheirSignedPreKey(bobBaseKey.getPublicKey());
    aliceParameters.setTheirIdentityKey(bobIdentityKey.getPublicKey());

    BobAxolotlParameters bobParameters;
    bobParameters.setOurRatchetKey(bobEphemeralKey);
    bobParameters.setOurSignedPreKey(bobBaseKey);
    bobParameters.setOurIdentityKey(bobIdentityKey);
    bobParameters.setTheirIdentityKey(aliceIdentityKey.getPublicKey());
    bobParameters.setTheirBaseKey(aliceBaseKey.getPublicKey());

    RatchetingSession::initializeSession(aliceSessionState, 3, aliceParameters);
    RatchetingSession::initializeSession(bobSessionState, 3, bobParameters);
}
