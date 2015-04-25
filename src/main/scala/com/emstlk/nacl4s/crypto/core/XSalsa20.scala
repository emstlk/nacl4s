package com.emstlk.nacl4s.crypto.core

import com.emstlk.nacl4s.crypto.Utils._

object XSalsa20 {

  val crypto_stream_xsalsa20_KEYBYTES = 32
  val crypto_stream_xsalsa20_NONCEBYTES = 24

  def cryptoStream(c: Array[Byte],
                   clen: Int,
                   n: Array[Byte],
                   k: Array[Byte]): Int = {

    val subkey = new Array[Byte](32)
    HSalsa20.cryptoCore(subkey, n, k, getSigma)
    Salsa20.cryptoStream(c, clen, n, 16, subkey)
  }

  def cryptoStreamXor(c: Array[Byte],
                      m: Array[Byte],
                      mlen: Int,
                      n: Array[Byte],
                      k: Array[Byte]): Int = {

    val subkey = new Array[Byte](32)
    HSalsa20.cryptoCore(subkey, n, k, getSigma)
    Salsa20.cryptoStreamXor(c, m, mlen, n, 16, subkey)
  }

}