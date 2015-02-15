#include "inmemoryaxolotlstore.h"

#include <QDebug>

InMemoryAxolotlStore::InMemoryAxolotlStore()
{
}

IdentityKeyPair InMemoryAxolotlStore::getIdentityKeyPair()
{
    return identityKeyStore.getIdentityKeyPair();
}

int InMemoryAxolotlStore::getLocalRegistrationId()
{
    return identityKeyStore.getLocalRegistrationId();
}

void InMemoryAxolotlStore::saveIdentity(long recipientId, const IdentityKey &identityKey)
{
    identityKeyStore.saveIdentity(recipientId, identityKey);
}

bool InMemoryAxolotlStore::isTrustedIdentity(long recipientId, const IdentityKey &identityKey)
{
    return identityKeyStore.isTrustedIdentity(recipientId, identityKey);
}

PreKeyRecord InMemoryAxolotlStore::loadPreKey(int preKeyId)
{
    return preKeyStore.loadPreKey(preKeyId);
}

void InMemoryAxolotlStore::storePreKey(int preKeyId, const PreKeyRecord &record)
{
    preKeyStore.storePreKey(preKeyId, record);
}

bool InMemoryAxolotlStore::containsPreKey(int preKeyId)
{
    return preKeyStore.containsPreKey(preKeyId);
}

void InMemoryAxolotlStore::removePreKey(int preKeyId)
{
    preKeyStore.removePreKey(preKeyId);
}

SessionRecord *InMemoryAxolotlStore::loadSession(long recipientId, int deviceId)
{
    return sessionStore.loadSession(recipientId, deviceId);
}

QList<int> InMemoryAxolotlStore::getSubDeviceSessions(long recipientId)
{
    return sessionStore.getSubDeviceSessions(recipientId);
}

void InMemoryAxolotlStore::storeSession(long recipientId, int deviceId, SessionRecord *record)
{
    sessionStore.storeSession(recipientId, deviceId, record);
}

bool InMemoryAxolotlStore::containsSession(long recipientId, int deviceId)
{
    return sessionStore.containsSession(recipientId, deviceId);
}

void InMemoryAxolotlStore::deleteSession(long recipientId, int deviceId)
{
    sessionStore.deleteSession(recipientId, deviceId);
}

void InMemoryAxolotlStore::deleteAllSessions(long recipientId)
{
    sessionStore.deleteAllSessions(recipientId);
}

SignedPreKeyRecord InMemoryAxolotlStore::loadSignedPreKey(int signedPreKeyId)
{
    return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
}

QList<SignedPreKeyRecord> InMemoryAxolotlStore::loadSignedPreKeys()
{
    return signedPreKeyStore.loadSignedPreKeys();
}

void InMemoryAxolotlStore::storeSignedPreKey(int signedPreKeyId, const SignedPreKeyRecord &record)
{
    signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
}

bool InMemoryAxolotlStore::containsSignedPreKey(int signedPreKeyId)
{
    return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
}

void InMemoryAxolotlStore::removeSignedPreKey(int signedPreKeyId)
{
    signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
}
