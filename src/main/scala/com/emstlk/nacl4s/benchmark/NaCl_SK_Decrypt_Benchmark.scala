package com.emstlk.nacl4s.benchmark

import com.emstlk.nacl4s.crypto.SecretBox
import org.openjdk.jmh.annotations._

// In that case a single key is used to encrypt and decrypt messages.

@State(Scope.Thread)
class NaCl_SK_Decrypt_Benchmark {

  var myBox: SecretBox = _
  var key: Array[Byte] = _
  var nonce: Array[Byte] = _
  var friendBox: SecretBox = _

  @Param(Array("128", "512", "1024", "2048"))
  var sizeMessage: String = _

  var message: Array[Byte] = _

  var messageEncrypted: Array[Byte] = _

  @Setup(Level.Trial)
  def setUp(): Unit = {
    myBox = SecretBox.withRandomKey()
    key = myBox.key
    nonce = SecretBox.randomNonce()
    message = Array.tabulate(sizeMessage.toInt)(_.toByte)
    messageEncrypted = myBox.encrypt(nonce, message)

    friendBox = SecretBox(key)
  }

  @Benchmark
  def decrypt(): Unit = {
    friendBox.decrypt(nonce, messageEncrypted)
  }

}
