#ifndef INMEMORYSIGNEDPREKEYSTORE_H
#define INMEMORYSIGNEDPREKEYSTORE_H

#include "../libaxolotl/state/signedprekeystore.h"

#include <QHash>

class InMemorySignedPreKeyStore : public SignedPreKeyStore
{
public:
    InMemorySignedPreKeyStore();
    SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId);
    QList<SignedPreKeyRecord> loadSignedPreKeys();
    void storeSignedPreKey(int signedPreKeyId, const SignedPreKeyRecord &record);
    bool containsSignedPreKey(int signedPreKeyId);
    void removeSignedPreKey(int signedPreKeyId);

private:
    QHash<int, QByteArray> store;
};

#endif // INMEMORYSIGNEDPREKEYSTORE_H
