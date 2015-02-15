#include "chainkeytest.h"

#include <QByteArray>
#include <QDebug>

#include "../libaxolotl/ratchet/chainkey.h"
#include "../libaxolotl/kdf/hkdf.h"

ChainKeyTest::ChainKeyTest()
{
}

void ChainKeyTest::testChainKeyDerivationV2()
{
    qDebug() << "testChainKeyDerivationV2";

    QByteArray         seed = QByteArray::fromHex("8ab72d6f4cc5ac0d387eaf463378ddb28edd07385b1cb01250c715982e7ad48f");
    QByteArray   messageKey = QByteArray::fromHex("02a9aa6c7dbd64f9d3aa92f92a277bf54609dadf0b00828acfc61e3c724b84a7");
    QByteArray       macKey = QByteArray::fromHex("bfbe5efb603030526742e3ee89c7024e884e440f1ff376bb2317b2d64deb7c83");
    QByteArray nextChainKey = QByteArray::fromHex("28e8f8fee54b801eef7c5cfb2f17f32c7b334485bbb70fac6ec10342a246d15d");

    HKDF kdf(2);
    ChainKey chainKey(kdf, seed, 0);

    bool verified = chainKey.getKey() == seed
            && chainKey.getMessageKeys().getCipherKey() == messageKey
            && chainKey.getMessageKeys().getMacKey() == macKey
            && chainKey.getNextChainKey().getKey() == nextChainKey
            && chainKey.getIndex() == 0
            && chainKey.getMessageKeys().getCounter() == 0
            && chainKey.getNextChainKey().getIndex() == 1
            && chainKey.getNextChainKey().getMessageKeys().getCounter() == 1;

    qDebug() << "VERIFIED" << verified;

    if (!verified) {
        qDebug() << "getKey:      " << chainKey.getKey().toHex();
        qDebug() << "getCipherKey:" << chainKey.getMessageKeys().getCipherKey().toHex();
        qDebug() << "getMacKey:   " << chainKey.getMessageKeys().getMacKey().toHex();
        qDebug() << "nextKey:     " << chainKey.getNextChainKey().getKey().toHex();
        qDebug() << "getIndex:    " << chainKey.getIndex();
        qDebug() << "getCounter:  " << chainKey.getMessageKeys().getCounter();
        qDebug() << "nextIndex:   " << chainKey.getNextChainKey().getIndex();
        qDebug() << "nextCounter: " << chainKey.getNextChainKey().getMessageKeys().getCounter();
    }
}
