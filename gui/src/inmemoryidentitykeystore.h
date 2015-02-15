#ifndef INMEMORYIDENTITYKEYSTORE_H
#define INMEMORYIDENTITYKEYSTORE_H

#include "../libaxolotl/state/identitykeystore.h"
#include "../libaxolotl/identitykeypair.h"
#include "../libaxolotl/util/keyhelper.h"

#include <QHash>

class InMemoryIdentityKeyStore : public IdentityKeyStore
{
public:
    InMemoryIdentityKeyStore();

    IdentityKeyPair getIdentityKeyPair();
    int             getLocalRegistrationId();
    void            saveIdentity(long recipientId, const IdentityKey &identityKey);
    bool            isTrustedIdentity(long recipientId, const IdentityKey &identityKey);

private:
    QHash<long, IdentityKey> trustedKeys;
    IdentityKeyPair identityKeyPair;
    unsigned long localRegistrationId;
};

#endif // INMEMORYIDENTITYKEYSTORE_H
