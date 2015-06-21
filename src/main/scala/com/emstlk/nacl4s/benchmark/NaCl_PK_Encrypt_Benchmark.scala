package com.emstlk.nacl4s.benchmark

import com.emstlk.nacl4s._
import org.openjdk.jmh.annotations._

// This approach allows you encrypt a secret message for your friend, using friend's public key.

@State(Scope.Thread)
class NaCl_PK_Encrypt_Benchmark {

  var myKeys: crypto.KeyPair = _
  var friendKeys: crypto.KeyPair = _
  var myBox: crypto.Box = _
  var nonce: Array[Byte] = _

  @Param(Array("128", "512", "1024", "2048"))
  var sizeMessage: String = _

  var message: Array[Byte] = _

  @Setup(Level.Trial)
  def setUp(): Unit = {
    myKeys = KeyPair()
    friendKeys = KeyPair()

    myBox = Box(friendKeys.publicKey, myKeys.privateKey)
    nonce = Box.randomNonce()

    message = Array.tabulate(sizeMessage.toInt)(_.toByte)
  }

  @Benchmark
  def encrypt(): Unit = {
    myBox.encrypt(nonce, message)
  }

}
