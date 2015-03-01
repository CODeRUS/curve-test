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

        QSharedPointer<PreKeyWhisperMessage> incomingMessage(new PreKeyWhisperMessage(outgoingMessageSerialized));
        bobStore->storePreKey(31337, PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));


        SessionCipher bobSessionCipher(bobStore, ALICE_RECIPIENT_ID, 1);
        QByteArray plaintext = bobSessionCipher.decrypt(incomingMessage);

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
