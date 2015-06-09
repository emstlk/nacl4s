package com.emstlk.nacl4s.crypto

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.sign.Ed25519._

object SigningKeyPair {

  def apply(): SigningKeyPair = {
    val privateKey = new Array[Byte](secretKeyBytes)
    val publicKey = new Array[Byte](publicKeyBytes)
    cryptoSignKeyPair(publicKey, privateKey)
    SigningKeyPair(SigningKey(privateKey), VerifyKey(publicKey))
  }

  def apply(seed: Array[Byte]): SigningKeyPair = {
    checkLength(seed, seedBytes)
    val privateKey = new Array[Byte](secretKeyBytes)
    val publicKey = new Array[Byte](publicKeyBytes)
    cryptoSignSeedKeyPair(publicKey, privateKey, seed)
    SigningKeyPair(SigningKey(privateKey), VerifyKey(publicKey))
  }

}

case class SigningKeyPair(signingKey: SigningKey, verifyKey: VerifyKey)

case class SigningKey(key: Array[Byte]) {
  checkLength(key, secretKeyBytes)

  def sign(message: Array[Byte]) = {
    val data = new Array[Byte](bytes) ++ message
    cryptoSign(data, message, message.length, key)
    data.take(bytes)
  }
}

case class VerifyKey(key: Array[Byte]) {
  checkLength(key, publicKeyBytes)

  def verify(message: Array[Byte], signature: Array[Byte]) {
    checkLength(signature, bytes)
    val data = signature ++ message
    cryptoSignOpen(message, data, data.length, key)
  }
}
