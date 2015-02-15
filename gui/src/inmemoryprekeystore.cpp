#include "inmemoryprekeystore.h"

#include "../libaxolotl/invalidkeyidexception.h"

InMemoryPreKeyStore::InMemoryPreKeyStore()
{
}

PreKeyRecord InMemoryPreKeyStore::loadPreKey(int preKeyId)
{
    if (!store.contains(preKeyId)) {
        throw new InvalidKeyIdException("No such prekeyRecord!");
    }
    return PreKeyRecord(store[preKeyId]);
}

void InMemoryPreKeyStore::storePreKey(int preKeyId, const PreKeyRecord &record)
{
    store[preKeyId] = record.serialize();
}

bool InMemoryPreKeyStore::containsPreKey(int preKeyId)
{
    return store.contains(preKeyId);
}

void InMemoryPreKeyStore::removePreKey(int preKeyId)
{
    if (store.contains(preKeyId)) {
        store.remove(preKeyId);
    }
}
