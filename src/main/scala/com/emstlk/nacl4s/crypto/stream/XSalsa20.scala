package com.emstlk.nacl4s.crypto.stream

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.core.{HSalsa20, Salsa20}

object XSalsa20 {

  val keyBytes = 32
  val nonceBytes = 24

  def cryptoStream(c: Array[Byte], clen: Int, n: Array[Byte], k: Array[Byte]) {
    val subkey = new Array[Byte](keyBytes)
    HSalsa20.cryptoCore(subkey, n, k, getSigma)
    Salsa20.cryptoStream(c, clen, n, 16, subkey)
  }

  def cryptoStreamXor(c: Array[Byte], m: Array[Byte], mlen: Int, n: Array[Byte], k: Array[Byte]) {
    val subkey = new Array[Byte](keyBytes)
    HSalsa20.cryptoCore(subkey, n, k, getSigma)
    Salsa20.cryptoStreamXor(c, m, mlen, n, 16, subkey)
  }

}