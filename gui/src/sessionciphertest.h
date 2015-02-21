#ifndef SESSIONCIPHERTEST_H
#define SESSIONCIPHERTEST_H

#include "../libaxolotl/state/sessionstate.h"
#include "../libaxolotl/state/sessionrecord.h"

class SessionCipherTest
{
public:
    SessionCipherTest();

    void simpleTest();

    void testBasicSessionV2();
    void testBasicSessionV3();

private:
    void runInteraction(SessionRecord *aliceSessionRecord, SessionRecord *bobSessionRecord);

    void initializeSessionsV2(SessionState *aliceSessionState, SessionState *bobSessionState);
    void initializeSessionsV3(SessionState *aliceSessionState, SessionState *bobSessionState);

    QByteArray getCiphertextV3(const QByteArray &key, QByteArray &iv, const QByteArray &plaintext);
    QByteArray getCiphertextV2(const QByteArray &key, unsigned int counter, const QByteArray &plaintext);

    QByteArray getPlaintextV3(const QByteArray &key, QByteArray &iv, const QByteArray &ciphertext);
    QByteArray getPlaintextV2(const QByteArray &key, unsigned int counter, const QByteArray &ciphertext);
};

#endif // SESSIONCIPHERTEST_H
