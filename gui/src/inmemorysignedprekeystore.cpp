#include "inmemorysignedprekeystore.h"

#include "../libaxolotl/invalidkeyidexception.h"

InMemorySignedPreKeyStore::InMemorySignedPreKeyStore()
{
}

SignedPreKeyRecord InMemorySignedPreKeyStore::loadSignedPreKey(int signedPreKeyId)
{
    if (store.contains(signedPreKeyId)) {
        return SignedPreKeyRecord(store[signedPreKeyId]);
    }
    throw new InvalidKeyIdException(QString("No such signedprekeyrecord! %1 ").arg(signedPreKeyId));
}

QList<SignedPreKeyRecord> InMemorySignedPreKeyStore::loadSignedPreKeys()
{
    QList<SignedPreKeyRecord> results;
    foreach (const QByteArray &serialized, store.values()) {
        results.append(SignedPreKeyRecord(serialized));
    }
    return results;
}

void InMemorySignedPreKeyStore::storeSignedPreKey(int signedPreKeyId, const SignedPreKeyRecord &record)
{
    store[signedPreKeyId] = record.serialize();
}

bool InMemorySignedPreKeyStore::containsSignedPreKey(int signedPreKeyId)
{
    return store.contains(signedPreKeyId);
}

void InMemorySignedPreKeyStore::removeSignedPreKey(int signedPreKeyId)
{
    if (store.contains(signedPreKeyId)) {
        store.remove(signedPreKeyId);
    }
}
