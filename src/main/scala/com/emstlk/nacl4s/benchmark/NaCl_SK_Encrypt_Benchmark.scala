package com.emstlk.nacl4s.benchmark

import com.emstlk.nacl4s.crypto.SecretBox
import org.openjdk.jmh.annotations._

// In that case a single key is used to encrypt and decrypt messages.

@State(Scope.Thread)
class NaCl_SK_Encrypt_Benchmark {
  var myBox: SecretBox = _
  var key: Array[Byte] = _
  var nonce: Array[Byte] = _

  @Param(Array("128", "512", "1024", "2048"))
  var sizeMessage: String = _

  var message: Array[Byte] = _

  @Setup(Level.Trial)
  def setUp(): Unit = {
    myBox = SecretBox.withRandomKey()
    key = myBox.key
    nonce = SecretBox.randomNonce()
    message = Array.tabulate(sizeMessage.toInt)(_.toByte)
  }

  @Benchmark
  def encrypt(): Unit = {
    myBox.encrypt(nonce, message)
  }

}
