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

void SessionCipherTest::simpleTest()
{
    qDebug() << "simpleTest";

    QByteArray data("Test message");

    QByteArray key128(16, 'z');
    unsigned int counter = 0;

    QByteArray ciphertextv2 = getCiphertextV2(key128, counter, data);
    QByteArray plaintextv2 = getPlaintextV2(key128, counter, ciphertextv2);
    if (plaintextv2 != data) {
        qDebug() << "[V2] FAILED";
    }
    else {
        qDebug() << "[V2] PASSED";
    }

    QByteArray key256(32, 'z');
    QByteArray ivec(16, 'x');
    QByteArray iv1(ivec);
    QByteArray iv2(ivec);

    QByteArray ciphertextv3 = getCiphertextV3(key256, iv1, data);
    QByteArray plaintextv3 = getPlaintextV3(key256, iv2, ciphertextv3);
    if (plaintextv3 != data) {
        qDebug() << "[V3] FAILED";
    }
    else {
        qDebug() << "[V3] PASSED";
    }
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
    qDebug() << "TEST3";
    for (int i = 0; i < aliceCiphertextMessages.size() / 2; i++) {
        QSharedPointer<WhisperMessage> decryptMessage(new WhisperMessage(aliceCiphertextMessages[i]->serialize()));
        QByteArray receivedPlaintext = bobCipher.decrypt(decryptMessage);

        bool passed3 = receivedPlaintext == alicePlaintextMessages[i];
        //qDebug() << "PASSED 3" << passed3;

        if (!passed3) {
            qDebug() << QString("receivedPlaintext[%1]     ").arg(i) << receivedPlaintext.toHex();
            qDebug() << QString("alicePlaintextMessages[%1]").arg(i) << alicePlaintextMessages[i].toHex();
        }
    }

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

    qDebug() << "TEST4";
    for (int i = 0; i < bobCiphertextMessages.size() / 2; i++) {
        QSharedPointer<WhisperMessage> decryptMessage(new WhisperMessage(bobCiphertextMessages[i]->serialize()));
        QByteArray receivedPlaintext = aliceCipher.decrypt(decryptMessage);

        bool passed4 = receivedPlaintext == bobPlaintextMessages[i];
        //qDebug() << "PASSED 4" << passed4;

        if (!passed4) {
            qDebug() << QString("receivedPlaintext[%1]   ").arg(i) << receivedPlaintext.toHex();
            qDebug() << QString("bobPlaintextMessages[%1]").arg(i) << bobPlaintextMessages[i].toHex();
        }
    }

    qDebug() << "TEST5";
    for (int i = aliceCiphertextMessages.size() / 2; i < aliceCiphertextMessages.size(); i++) {
        QSharedPointer<WhisperMessage> decryptMessage(new WhisperMessage(aliceCiphertextMessages[i]->serialize()));
        QByteArray receivedPlaintext = bobCipher.decrypt(decryptMessage);

        bool passed5 = receivedPlaintext == alicePlaintextMessages[i];
        //qDebug() << "PASSED 5" << passed5;

        if (!passed5) {
            qDebug() << QString("receivedPlaintext[%1]     ").arg(i) << receivedPlaintext.toHex();
            qDebug() << QString("alicePlaintextMessages[%1]").arg(i) << alicePlaintextMessages[i].toHex();
        }
    }

    qDebug() << "TEST6";
    for (int i = bobCiphertextMessages.size() / 2; i < bobCiphertextMessages.size(); i++) {
        QSharedPointer<WhisperMessage> decryptMessage(new WhisperMessage(bobCiphertextMessages[i]->serialize()));
        QByteArray receivedPlaintext = aliceCipher.decrypt(decryptMessage);

        bool passed6 = receivedPlaintext == bobPlaintextMessages[i];
        //qDebug() << "PASSED 6" << passed6;

        if (!passed6) {
            qDebug() << QString("receivedPlaintext[%1]   ").arg(i) << receivedPlaintext.toHex();
            qDebug() << QString("bobPlaintextMessages[%1]").arg(i) << bobPlaintextMessages[i].toHex();
        }
    }
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

QByteArray SessionCipherTest::getPlaintextV2(const QByteArray &key, unsigned int counter, const QByteArray &ciphertext)
{
    AES_KEY dec_key;
    AES_set_encrypt_key((const unsigned char*)key.constData(), key.size() * 8, &dec_key);
    QByteArray out(ciphertext.size(), '\0');
    QByteArray iv(AES_BLOCK_SIZE, '\0');
    ByteUtil::intToByteArray(iv, 0, counter);
    unsigned char ecount[AES_BLOCK_SIZE];
    memset(ecount, 0, AES_BLOCK_SIZE);
    AES_ctr128_encrypt((unsigned char*)ciphertext.constData(), (unsigned char*)out.data(),
                       ciphertext.size(), &dec_key, (unsigned char*)iv.constData(),
                       ecount, &counter);
    return out;
}

QByteArray SessionCipherTest::getPlaintextV3(const QByteArray &key, QByteArray &iv, const QByteArray &ciphertext)
{
    AES_KEY dec_key;
    AES_set_decrypt_key((const unsigned char*)key.constData(), key.size() * 8, &dec_key);
    QByteArray out(ciphertext.size(), '\0');
    AES_cbc_encrypt((const unsigned char*)ciphertext.constData(),
                    (unsigned char*)out.data(),
                    ciphertext.size(), &dec_key,
                    (unsigned char*)iv.data(), AES_DECRYPT);
    out.resize(out.size() - out.right(1)[0]);
    return out;
}

QByteArray SessionCipherTest::getCiphertextV2(const QByteArray &key, unsigned int counter, const QByteArray &plaintext)
{
    AES_KEY enc_key;
    AES_set_encrypt_key((const unsigned char*)key.constData(), key.size() * 8, &enc_key);
    QByteArray out(plaintext.size(), '\0');
    QByteArray iv(AES_BLOCK_SIZE, '\0');
    ByteUtil::intToByteArray(iv, 0, counter);
    unsigned char ecount[AES_BLOCK_SIZE];
    memset(ecount, 0, AES_BLOCK_SIZE);
    AES_ctr128_encrypt((unsigned char*)plaintext.constData(), (unsigned char*)out.data(),
                       plaintext.size(), &enc_key, (unsigned char*)iv.constData(),
                       ecount, &counter);
    return out;
}

QByteArray SessionCipherTest::getCiphertextV3(const QByteArray &key, QByteArray &iv, const QByteArray &plaintext)
{
    AES_KEY enc_key;
    AES_set_encrypt_key((const unsigned char*)key.constData(), key.size() * 8, &enc_key);
    QByteArray padText = plaintext;
    int padlen = ((padText.size() + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE - plaintext.size();
    padText.append(QByteArray(padlen, (char)padlen));
    QByteArray out(padText.size(), '\0');
    AES_cbc_encrypt((const unsigned char*)padText.constData(), (unsigned char*)out.data(),
                    padText.size(), &enc_key,
                    (unsigned char*)iv.data(), AES_ENCRYPT);
    return out;
}
