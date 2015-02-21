#include "sessionbuildertest.h"

#include "inmemoryaxolotlstore.h"

#include "../libaxolotl/sessionbuilder.h"
#include "../libaxolotl/ecc/curve.h"
#include "../libaxolotl/sessioncipher.h"

#include "../libaxolotl/untrustedidentityexception.h"
#include "../libaxolotl/invalidkeyidexception.h"
#include "../libaxolotl/invalidkeyexception.h"
#include "../libaxolotl/invalidmessageexception.h"

#include "../libaxolotl/state/LocalStorageProtocol.pb.h"
#include "../libaxolotl/protocol/WhisperTextProtocol.pb.h"

#include <QDebug>

long SessionBuilderTest::ALICE_RECIPIENT_ID = 5;
long SessionBuilderTest::BOB_RECIPIENT_ID = 2;

SessionBuilderTest::SessionBuilderTest()
{
}

void SessionBuilderTest::testBasicPreKeyV2()
{
    try {
        qDebug() << "testBasicPreKeyV2";

        QSharedPointer<AxolotlStore> aliceStore(new InMemoryAxolotlStore());
        SessionBuilder aliceSessionBuilder(aliceStore, SessionBuilderTest::BOB_RECIPIENT_ID, 1);

        QSharedPointer<AxolotlStore> bobStore(new InMemoryAxolotlStore());
        ECKeyPair    bobPreKeyPair = Curve::generateKeyPair();
        PreKeyBundle bobPreKey(bobStore->getLocalRegistrationId(), 1,
                               31337, bobPreKeyPair.getPublicKey(),
                               0, DjbECPublicKey(), QByteArray(),
                               bobStore->getIdentityKeyPair().getPublicKey());

        aliceSessionBuilder.process(bobPreKey);

        bool containsSession = aliceStore->containsSession(BOB_RECIPIENT_ID, 1);
        int   sessionVersion = aliceStore->loadSession(BOB_RECIPIENT_ID, 1)->getSessionState()->getSessionVersion();

        bool passed1 = containsSession && sessionVersion == 2;

        qDebug() << "PASSED 1" << passed1;

        if (!passed1) {
            qDebug() << "don't know what to show...";
        }

        QByteArray        originalMessage("L'homme est condamné à être libre");
        SessionCipher    *aliceSessionCipher = new SessionCipher(aliceStore, BOB_RECIPIENT_ID, 1);
        QSharedPointer<CiphertextMessage> outgoingMessage = aliceSessionCipher->encrypt(originalMessage);

        bool passed2 = outgoingMessage->getType() == CiphertextMessage::PREKEY_TYPE;

        qDebug() << "PASSED 2" << passed2;

        if (!passed2) {
            qDebug() << "CiphertextMessage::getType" << outgoingMessage->getType();
        }

        QByteArray outgoingMessageSerialized = outgoingMessage->serialize();
        qDebug() << "Stage 0";

        PreKeyWhisperMessage testMessage(QByteArray::fromHex("2308e9f401122105db5e6eb1a65595ae56482995a94fb9400af928d4d73bb548ed493c13a305bb3d1a2105f08eef48c14f94c7c5ebc9fb5c7dc6fe867567920c285aa90983220d2509b94c2256230a2105767fc2f37de0b8130e1808cf6b505c636d118adcb99f793d14f5bc263a6ae44610001800222466b9df118ebd28c7064ef7f6c0366205bf56160e6592c6358311944402e3167382f8670298653b59b1cbf76d28fbb4d8fb093000"));
        qDebug() << "test ciphertext:" << testMessage.serialize().toHex();

        /*QByteArray testMessageSerialized = QByteArray::fromHex("0a2105efdceaa2bff3c6b17c3fd583b164a8a3ed62a2de2b965099f237a9ddc63a4825100018002224a0a2ddf9efa56048b1b76bc6de57b859dceb4993c6ecfad9b5cd1bf400a33fc31d61a159");
        textsecure::WhisperMessage whisperMessage;
        whisperMessage.ParseFromArray(testMessageSerialized.constData(), testMessageSerialized.size());

        qDebug() << "has_ciphertext" << whisperMessage.has_ciphertext();
        qDebug() << "has_counter" << whisperMessage.has_counter();
        qDebug() << "has_ratchetkey" << whisperMessage.has_ratchetkey();*/

        QSharedPointer<PreKeyWhisperMessage> incomingMessage(new PreKeyWhisperMessage(outgoingMessageSerialized));
        qDebug() << "Stage 1";
        bobStore->storePreKey(31337, PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));

        qDebug() << "Stage 2";

        SessionCipher bobSessionCipher(bobStore, ALICE_RECIPIENT_ID, 1);
        qDebug() << "Stage 3";
        QByteArray plaintext = bobSessionCipher.decrypt(incomingMessage);
        qDebug() << "Stage 4";

        bool passed3 = bobStore->containsSession(ALICE_RECIPIENT_ID, 1)
                && bobStore->loadSession(ALICE_RECIPIENT_ID, 1)->getSessionState()->getSessionVersion() == 2
                && originalMessage == plaintext;

        qDebug() << "PASSED 3" << passed3;

        if (!passed3) {
            qDebug() << "sessionVersion" << bobStore->loadSession(ALICE_RECIPIENT_ID, 1)->getSessionState()->getSessionVersion();
            qDebug() << "plaintext" << plaintext.toHex();
        }
    }
    catch (const UntrustedIdentityException &e) {
        qDebug() << "UntrustedIdentityException" << e.errorMessage();
    }
    catch (const InvalidKeyIdException &e) {
        qDebug() << "InvalidKeyIdException" << e.errorMessage();
    }
    catch (const InvalidKeyException &e) {
        qDebug() << "InvalidKeyException" << e.errorMessage();
    }
    catch (const InvalidMessageException &e) {
        qDebug() << "InvalidMessageException" << e.errorMessage();
    }
}
