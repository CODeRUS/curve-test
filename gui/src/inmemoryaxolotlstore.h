#ifndef INMEMORYAXOLOTLSTORE_H
#define INMEMORYAXOLOTLSTORE_H

#include "../libaxolotl/state/axolotlstore.h"

#include "inmemoryidentitykeystore.h"
#include "inmemoryprekeystore.h"
#include "inmemorysessionstore.h"
#include "inmemorysignedprekeystore.h"

#include <QList>

#include "../libaxolotl/state/identitykeystore.h"
#include "../libaxolotl/identitykeypair.h"
#include "../libaxolotl/util/keyhelper.h"
#include "../libaxolotl/state/prekeystore.h"
#include "../libaxolotl/state/sessionstore.h"
#include "../libaxolotl/state/sessionrecord.h"
#include "../libaxolotl/state/signedprekeystore.h"

class InMemoryAxolotlStore : public AxolotlStore
{
public:
    InMemoryAxolotlStore();

    IdentityKeyPair getIdentityKeyPair();
    int             getLocalRegistrationId();
    void            saveIdentity(long recipientId, const IdentityKey &identityKey);
    bool            isTrustedIdentity(long recipientId, const IdentityKey &identityKey);

    PreKeyRecord loadPreKey(int preKeyId);
    void         storePreKey(int preKeyId, const PreKeyRecord &record);
    bool         containsPreKey(int preKeyId);
    void         removePreKey(int preKeyId);

    SessionRecord *loadSession(long recipientId, int deviceId);
    QList<int> getSubDeviceSessions(long recipientId);
    void storeSession(long recipientId, int deviceId, SessionRecord *record);
    bool containsSession(long recipientId, int deviceId);
    void deleteSession(long recipientId, int deviceId);
    void deleteAllSessions(long recipientId);

    SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId);
    QList<SignedPreKeyRecord> loadSignedPreKeys();
    void storeSignedPreKey(int signedPreKeyId, const SignedPreKeyRecord &record);
    bool containsSignedPreKey(int signedPreKeyId);
    void removeSignedPreKey(int signedPreKeyId);

private:
    InMemoryIdentityKeyStore  identityKeyStore;
    InMemoryPreKeyStore       preKeyStore;
    InMemorySessionStore      sessionStore;
    InMemorySignedPreKeyStore signedPreKeyStore;
};

#endif // INMEMORYAXOLOTLSTORE_H
