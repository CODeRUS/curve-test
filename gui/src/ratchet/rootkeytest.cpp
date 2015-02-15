#include "rootkeytest.h"

#include <QByteArray>
#include <QDebug>

#include "../libaxolotl/ecc/curve.h"
#include "../libaxolotl/ecc/djbec.h"
#include "../libaxolotl/ecc/eckeypair.h"
#include "../libaxolotl/kdf/hkdf.h"
#include "../libaxolotl/ratchet/rootkey.h"

RootKeyTest::RootKeyTest()
{
}

void RootKeyTest::testRootKeyDerivationV2()
{
    qDebug() << "testRootKeyDerivationV2";

    QByteArray rootKeySeed  = QByteArray::fromHex("7ba6debc2bc1bbf91abbc1367404176ca623095b7ec66b45f602d93538942dcc");
    QByteArray alicePublic  = QByteArray::fromHex("05ee4fa6cdc030df49ecd0ba6cfcffb233d365a27fadbeff77e963fcb16222e13a");
    QByteArray alicePrivate = QByteArray::fromHex("216822ec67eb38049ebae7b939baeaebb151bbb32db80fd389245ac37a948e50");
    QByteArray bobPublic    = QByteArray::fromHex("05abb8eb29cc80b47109a2265abe9798485406e32da268934a9555e84757708a30");
    QByteArray nextRoot     = QByteArray::fromHex("b114f5de28011985e6eba25d50e7ec41a9b02f5693c5c788a63a06d212a2f731");
    QByteArray nextChain    = QByteArray::fromHex("9d7d2469bc9ae53ee9805aa3264d2499a3ace80f4ccae2da13430c5c55b5ca5f");

    DjbECPublicKey   alicePublicKey = Curve::decodePoint(alicePublic, 0);
    DjbECPrivateKey alicePrivateKey = Curve::decodePrivatePoint(alicePrivate);
    ECKeyPair          aliceKeyPair = ECKeyPair(alicePublicKey, alicePrivateKey);
    DjbECPublicKey     bobPublicKey = Curve::decodePoint(bobPublic, 0);
    RootKey                 rootKey = RootKey(HKDF(2), rootKeySeed);
    QPair<RootKey, ChainKey> rootKeyChainKeyPair = rootKey.createChain(bobPublicKey, aliceKeyPair);

    RootKey nextRootKey  = rootKeyChainKeyPair.first;
    ChainKey nextChainKey= rootKeyChainKeyPair.second;

    bool verified = rootKey.getKeyBytes() == rootKeySeed
             && nextRootKey.getKeyBytes() == nextRoot
                 && nextChainKey.getKey() == nextChain;

    qDebug() << "VERIFIED" << verified;

    if (!verified) {
        qDebug() << "alicePublicKey: " << alicePublicKey.serialize().toHex();
        qDebug() << "alicePrivateKey:" << alicePrivateKey.serialize().toHex();
        qDebug() << "bobPublicKey:   " << bobPublicKey.serialize().toHex();
        qDebug() << "rootKey:        " << rootKey.getKeyBytes().toHex();
        qDebug() << "nextRootKey:    " << nextRootKey.getKeyBytes().toHex();
        qDebug() << "nextChainKey:   " << nextChainKey.getKey().toHex();
    }
}
