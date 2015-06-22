# NaCl4s - NaCl library for Scala 

[![Build Status](https://travis-ci.org/emstlk/nacl4s.svg?branch=master)](https://travis-ci.org/emstlk/nacl4s)

## Overview
NaCl represents modern and powerful crypto library. 
That implementation was inspired by projects [libsodium](https://github.com/jedisct1/libsodium) and [kalium](https://github.com/abstractj/kalium)

Currently it has minimal functionality (box, secret box and signatures) based on algorithms:
- Salsa20
- HSalsa20
- XSalsa20
- Poly1305
- Curve25519
- Sha512
- Ed25519

## Installation

NaCl4s is published at Maven Central. Simply use the following sbt snippet:

```scala
libraryDependencies ++= Seq(
  "com.github.emstlk" %% "nacl4s" % "1.0.0"
)
```

## Using the library

#### Public-key authenticated encryption

This approach allows you to encrypt a secret message for your friend, using friend's public key.
You can read more details [here](http://doc.libsodium.org/public-key_cryptography/authenticated_encryption.html)

```scala
import com.emstlk.nacl4s._

val myKeys = KeyPair()
val friendKeys = KeyPair()

val myBox = Box(friendKeys.publicKey, myKeys.privateKey)
val nonce = Box.randomNonce()
val encrypted = myBox.encrypt(nonce, "See you tomorrow at my favourite place 😎️".asBytes)

val friendBox = Box(myKeys.publicKey, friendKeys.privateKey)
val message = friendBox.decrypt(nonce, encrypted).asString
```

#### Secret-key authenticated encryption

In that case a single key is used to encrypt and decrypt messages. 
More details [here](http://doc.libsodium.org/secret-key_cryptography/authenticated_encryption.html)

```scala
import com.emstlk.nacl4s._

val myBox = SecretBox.withRandomKey()
val key = myBox.key
val nonce = SecretBox.randomNonce()
val encrypted = myBox.encrypt(nonce, "Just another message".asBytes)

val friendBox = SecretBox(key)
val message = friendBox.decrypt(nonce, encrypted).asString
```

#### Public-key signatures

You can generate a key pair which allow you sign any message and anybody can verify it with your public key.
More details [here](http://doc.libsodium.org/public-key_cryptography/public-key_signatures.html)

```scala
import com.emstlk.nacl4s._

val keys = SigningKeyPair()
val message = "The new one message".asBytes
val signature = SigningKey(keys.privateKey).sign(message)

VerifyKey(keys.publicKey).verify(message, signature)
```

## Notes
NaCl4s is still a work in progress
