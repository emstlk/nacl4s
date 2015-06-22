package com.emstlk.nacl4s.benchmark

import com.emstlk.nacl4s.crypto.{SigningKey, SigningKeyPair}
import org.openjdk.jmh.annotations._

// Generate a key pair which allow you sign any message and anybody can verify it with your public key.

@State(Scope.Thread)
class NaCl_PK_Signature_Benchmark {

  var keys: SigningKeyPair = _

  @Param(Array("128", "512", "1024", "2048"))
  var sizeMessage: String = _

  var message: Array[Byte] = _

  @Setup(Level.Trial)
  def setUp(): Unit = {
    keys = SigningKeyPair()
    message = Array.tabulate(sizeMessage.toInt)(_.toByte)
  }

  @Benchmark
  def signature(): Unit = {
    SigningKey(keys.privateKey).sign(message)
  }

}
