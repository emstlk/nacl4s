package com.emstlk.nacl4s.crypto

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.sign.Ed25519._

object SigningKeyPair {

  def apply(): SigningKeyPair = {
    val privateKey = new Array[Byte](secretKeyBytes)
    val publicKey = new Array[Byte](publicKeyBytes)
    cryptoSignKeyPair(publicKey, privateKey)
    SigningKeyPair(privateKey, publicKey)
  }

  def apply(seed: Array[Byte]): SigningKeyPair = {
    checkLength(seed, seedBytes)
    val privateKey = new Array[Byte](secretKeyBytes)
    val publicKey = new Array[Byte](publicKeyBytes)
    cryptoSignSeedKeyPair(publicKey, privateKey, seed)
    SigningKeyPair(privateKey, publicKey)
  }

}

case class SigningKeyPair(privateKey: Array[Byte], publicKey: Array[Byte])

case class SigningKey(privateKey: Array[Byte]) {
  checkLength(privateKey, secretKeyBytes)

  def sign(message: Array[Byte]) = {
    val data = new Array[Byte](bytes) ++ message
    cryptoSign(data, message, message.length, privateKey)
    data.take(bytes)
  }
}

case class VerifyKey(publicKey: Array[Byte]) {
  checkLength(publicKey, publicKeyBytes)

  def verify(message: Array[Byte], signature: Array[Byte]) {
    checkLength(signature, bytes)
    val data = signature ++ message
    cryptoSignOpen(message, data, data.length, publicKey)
  }
}
