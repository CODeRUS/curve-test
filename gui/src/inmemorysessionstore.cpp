#include "inmemorysessionstore.h"

#include "../libaxolotl/state/LocalStorageProtocol.pb.h"

#include <QDebug>

InMemorySessionStore::InMemorySessionStore()
{
}

SessionRecord *InMemorySessionStore::loadSession(long recipientId, int deviceId)
{
    SessionsKeyPair key(recipientId, deviceId);
    if (sessions.contains(key)) {
        return new SessionRecord(sessions[key]);
    }
    else {
        return new SessionRecord();
    }
}

QList<int> InMemorySessionStore::getSubDeviceSessions(long recipientId)
{
    QList<int> deviceIds;

    foreach (const SessionsKeyPair &key, sessions.keys()) {
        if (key.first == recipientId) {
            deviceIds.append(key.second);
        }
    }

    return deviceIds;
}

void InMemorySessionStore::storeSession(long recipientId, int deviceId, SessionRecord *record)
{
    SessionsKeyPair key(recipientId, deviceId);
    QByteArray serialized = record->serialize();
    sessions[key] = serialized;
}

bool InMemorySessionStore::containsSession(long recipientId, int deviceId)
{
    SessionsKeyPair key(recipientId, deviceId);
    return sessions.contains(key);
}

void InMemorySessionStore::deleteSession(long recipientId, int deviceId)
{
    SessionsKeyPair key(recipientId, deviceId);
    if (sessions.contains(key)) {
        sessions.remove(key);
    }
}

void InMemorySessionStore::deleteAllSessions(long recipientId)
{
    foreach (const SessionsKeyPair &key, sessions.keys()) {
        if (key.first == recipientId) {
            sessions.remove(key);
        }
    }
}
