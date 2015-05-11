package com.emstlk.nacl4s

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.box.Curve25519XSalsa20Poly1305
import com.emstlk.nacl4s.crypto.scalarmult.Curve25519
import com.emstlk.nacl4s.crypto.secretbox.XSalsa20Poly1305

object NaCl {

  def box(keyPair: KeyPair) = new Box(keyPair.publicKey, keyPair.privateKey)

  def box(publicKey: Array[Byte], privateKey: Array[Byte]) = new Box(publicKey, privateKey)

  def secretBox(key: Array[Byte]) = new SecretBox(key)

  def newKeyPair = new KeyPair

  def keyPair(privateKey: Array[Byte]) = new KeyPair(privateKey)

}

class Box(publicKey: Array[Byte], privateKey: Array[Byte]) {

  import Curve25519XSalsa20Poly1305._

  checkLength(publicKey, publicKeyBytes)
  checkLength(privateKey, secretKeyBytes)

  def encrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, nonceBytes)
    val msg = new Array[Byte](zeroBytes) ++ message
    cryptoBox(msg, msg, msg.length, nonce, publicKey, privateKey)
    msg.drop(boxZeroBytes)
  }

  def decrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, nonceBytes)
    val msg = new Array[Byte](boxZeroBytes) ++ message
    cryptoBoxOpen(msg, msg, msg.length, nonce, publicKey, privateKey)
    msg.drop(zeroBytes)
  }

}

class SecretBox(key: Array[Byte]) {

  import XSalsa20Poly1305._

  checkLength(key, keyBytes)

  def encrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, nonceBytes)
    val msg = new Array[Byte](zeroBytes) ++ message
    cryptoSecretBox(msg, msg, msg.length, nonce, key)
    msg.drop(boxZeroBytes)
  }

  def decrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, nonceBytes)
    val msg = new Array[Byte](boxZeroBytes) ++ message
    cryptoSecretBoxOpen(msg, msg, msg.length, nonce, key)
    msg.drop(zeroBytes)
  }

}

class KeyPair private(val privateKey: Array[Byte], val publicKey: Array[Byte]) {

  checkLength(privateKey, Curve25519XSalsa20Poly1305.secretKeyBytes)

  def this() {
    this(
      new Array[Byte](Curve25519XSalsa20Poly1305.secretKeyBytes),
      new Array[Byte](Curve25519XSalsa20Poly1305.publicKeyBytes)
    )
    Curve25519XSalsa20Poly1305.cryptoBoxKeypair(publicKey, privateKey)
  }

  def this(privateKey: Array[Byte]) {
    this(privateKey, new Array[Byte](Curve25519XSalsa20Poly1305.publicKeyBytes))
    Curve25519.cryptoScalarmultBase(publicKey, privateKey)
  }

}
