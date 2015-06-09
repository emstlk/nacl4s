package com.emstlk.nacl4s.crypto

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.secretbox.XSalsa20Poly1305._

object SecretBox {

  def withRandomKey() = {
    val key = new Array[Byte](keyBytes)
    random.nextBytes(key)
    SecretBox(key)
  }

  def randomNonce() = {
    val nonce = new Array[Byte](nonceBytes)
    random.nextBytes(nonce)
    nonce
  }

}

case class SecretBox(key: Array[Byte]) {

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
