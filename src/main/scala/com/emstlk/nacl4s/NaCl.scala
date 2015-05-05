package com.emstlk.nacl4s

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.core.{Curve25519, Curve25519XSalsa20Poly1305, XSalsa20Poly1305}

object NaCl {

  def box(publicKey: Array[Byte], privateKey: Array[Byte]) = new Box(publicKey, privateKey)

  def secretBox(key: Array[Byte]) = new SecretBox(key)

  def newKeyPair = new KeyPair

  def keyPair(privateKey: Array[Byte]) = new KeyPair(privateKey)

}

class Box(publicKey: Array[Byte], privateKey: Array[Byte]) {

  checkLength(publicKey, 32)
  checkLength(privateKey, 32)

  def encrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, 24)
    val msg = new Array[Byte](32) ++ message
    Curve25519XSalsa20Poly1305.cryptoBox(msg, msg, msg.length, nonce, publicKey, privateKey)
    msg.drop(16)
  }

  def decrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, 24)
    val msg = new Array[Byte](16) ++ message
    Curve25519XSalsa20Poly1305.cryptoBoxOpen(msg, msg, msg.length, nonce, publicKey, privateKey)
    msg.drop(32)
  }

}

class SecretBox(key: Array[Byte]) {

  checkLength(key, 32)

  def encrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, 24)
    val msg = new Array[Byte](32) ++ message
    XSalsa20Poly1305.cryptoSecretBox(msg, msg, msg.length, nonce, key)
    msg.drop(16)
  }

  def decrypt(nonce: Array[Byte], message: Array[Byte]): Array[Byte] = {
    checkLength(nonce, 24)
    val msg = new Array[Byte](16) ++ message
    XSalsa20Poly1305.cryptoSecretBoxOpen(msg, msg, msg.length, nonce, key)
    msg.drop(32)
  }

}

class KeyPair private(val privateKey: Array[Byte], val publicKey: Array[Byte]) {

  checkLength(privateKey, 24)
  checkLength(publicKey, 24)

  def this() {
    this(new Array[Byte](32), new Array[Byte](32))
    Curve25519XSalsa20Poly1305.cryptoBoxKeypair(publicKey, privateKey)
  }

  def this(privateKey: Array[Byte]) {
    this(privateKey, new Array[Byte](32))
    Curve25519.cryptoScalarmultBase(publicKey, privateKey)
  }

}
