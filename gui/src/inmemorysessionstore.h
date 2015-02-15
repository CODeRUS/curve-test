#ifndef INMEMORYSESSIONSTORE_H
#define INMEMORYSESSIONSTORE_H

#include "../libaxolotl/state/sessionstore.h"
#include "../libaxolotl/state/sessionrecord.h"

#include <QPair>
#include <QHash>
#include <QByteArray>

typedef QPair<long, int> SessionsKeyPair;

class InMemorySessionStore : public SessionStore
{
public:
    InMemorySessionStore();
    SessionRecord *loadSession(long recipientId, int deviceId);
    QList<int> getSubDeviceSessions(long recipientId);
    void storeSession(long recipientId, int deviceId, SessionRecord *record);
    bool containsSession(long recipientId, int deviceId);
    void deleteSession(long recipientId, int deviceId);
    void deleteAllSessions(long recipientId);

private:
    QHash<SessionsKeyPair, QByteArray> sessions;
};

#endif // INMEMORYSESSIONSTORE_H
