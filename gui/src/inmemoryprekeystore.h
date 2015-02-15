#ifndef INMEMORYPREKEYSTORE_H
#define INMEMORYPREKEYSTORE_H

#include "../libaxolotl/state/prekeystore.h"

#include <QHash>
#include <QByteArray>

class InMemoryPreKeyStore : public PreKeyStore
{
public:
    InMemoryPreKeyStore();
    PreKeyRecord loadPreKey(int preKeyId);
    void         storePreKey(int preKeyId, const PreKeyRecord &record);
    bool         containsPreKey(int preKeyId);
    void         removePreKey(int preKeyId);

private:
    QHash<int, QByteArray> store;
};

#endif // INMEMORYPREKEYSTORE_H
