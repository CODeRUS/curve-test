#include "inmemoryidentitykeystore.h"

#include "../libaxolotl/ecc/curve.h"
#include "../libaxolotl/ecc/eckeypair.h"

#include <QDebug>

InMemoryIdentityKeyStore::InMemoryIdentityKeyStore()
{
    ECKeyPair identityKeyPairKeys = Curve::generateKeyPair();
    identityKeyPair = IdentityKeyPair(IdentityKey(identityKeyPairKeys.getPublicKey()),
                                      identityKeyPairKeys.getPrivateKey());
    localRegistrationId = KeyHelper::generateRegistrationId();
}

IdentityKeyPair InMemoryIdentityKeyStore::getIdentityKeyPair()
{
    return identityKeyPair;
}

int InMemoryIdentityKeyStore::getLocalRegistrationId()
{
    return localRegistrationId;
}

void InMemoryIdentityKeyStore::saveIdentity(long recipientId, const IdentityKey &identityKey)
{
    trustedKeys[recipientId] = identityKey;
}

bool InMemoryIdentityKeyStore::isTrustedIdentity(long recipientId, const IdentityKey &identityKey)
{
    if (!trustedKeys.contains(recipientId)) {
        return true;
    }
    return trustedKeys[recipientId] == identityKey;
}
