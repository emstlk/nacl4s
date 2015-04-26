package com.emstlk.nacl4s.crypto.core

import com.emstlk.nacl4s.crypto.Utils._

object XSalsa20 {

  val keybytes = 32
  val noncebytes = 24

  def encryptStream(c: Array[Byte], clen: Int, n: Array[Byte], k: Array[Byte]) {
    val subkey = new Array[Byte](32)
    HSalsa20.encrypt(subkey, n, k, getSigma)
    Salsa20.encryptStream(c, clen, n, 16, subkey)
  }

  def encryptStreamXor(c: Array[Byte], m: Array[Byte], mlen: Int, n: Array[Byte], k: Array[Byte]) {
    val subkey = new Array[Byte](32)
    HSalsa20.encrypt(subkey, n, k, getSigma)
    Salsa20.encryptStreamXor(c, m, mlen, n, 16, subkey)
  }

}