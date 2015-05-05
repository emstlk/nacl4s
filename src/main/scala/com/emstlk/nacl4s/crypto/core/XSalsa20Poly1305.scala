package com.emstlk.nacl4s.crypto.core

object XSalsa20Poly1305 {

  val keybytes = 32
  val noncebytes = 24
  val zerobytes = 32
  val boxzerobytes = 16

  def cryptoSecretBox(c: Array[Byte], m: Array[Byte], mlen: Int, n: Array[Byte], k: Array[Byte]) {
    require(mlen >= 32)

    XSalsa20.cryptoStreamXor(c, m, mlen, n, k)
    Poly1305.cryptoOneTimeAuth(c, 16, c, 32, mlen - 32, c)

    for (i <- 0 until 16) c(i) = 0
  }

  def cryptoSecretBoxOpen(m: Array[Byte], c: Array[Byte], clen: Int, n: Array[Byte], k: Array[Byte]) {
    require(clen >= 32)

    val subkey = new Array[Byte](32)
    XSalsa20.cryptoStream(subkey, 32, n, k)

    Poly1305.cryptoOneTimeAuthVerify(c, 16, c, 32, clen - 32, subkey)
    XSalsa20.cryptoStreamXor(m, c, clen, n, k)

    for (i <- 0 until 32) m(i) = 0
  }

}
