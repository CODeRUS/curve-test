TARGET = curve-test

CONFIG += sailfishapp link_pkgconfig
PKGCONFIG += sailfishapp openssl libssl libcrypto protobuf

LIBS += -L../libcurve25519 -lcurve25519
LIBS += -L../libaxolotl -laxolotl

HEADERS += \
    ../libcurve25519/curve.h \
    ../libcurve25519/curve_global.h \
    ../libaxolotl/ecc/curve.h \
    ../libaxolotl/util/keyhelper.h \
    src/curve25519test.h \
    src/groups/inmemorysenderkeystore.h \
    src/inmemoryidentitykeystore.h \
    src/inmemoryprekeystore.h \
    src/inmemorysessionstore.h \
    src/inmemorysignedprekeystore.h \
    src/ratchet/rootkeytest.h \
    src/kdf/hkdftest.h \
    src/ratchet/chainkeytest.h \
    src/ratchet/ratchetingsessiontest.h \
    src/sessionbuildertest.h \
    src/inmemoryaxolotlstore.h \
    src/sessionciphertest.h

SOURCES += \
    src/curve-test.cpp \
    src/curve25519test.cpp \
    src/groups/inmemorysenderkeystore.cpp \
    src/inmemoryidentitykeystore.cpp \
    src/inmemoryprekeystore.cpp \
    src/inmemorysessionstore.cpp \
    src/inmemorysignedprekeystore.cpp \
    src/ratchet/rootkeytest.cpp \
    src/kdf/hkdftest.cpp \
    src/ratchet/chainkeytest.cpp \
    src/ratchet/ratchetingsessiontest.cpp \
    src/sessionbuildertest.cpp \
    src/inmemoryaxolotlstore.cpp \
    src/sessionciphertest.cpp

OTHER_FILES += qml/curve-test.qml \
    qml/cover/CoverPage.qml \
    qml/pages/FirstPage.qml \
    qml/pages/SecondPage.qml \
    curve-test.desktop

