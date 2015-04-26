package com.emstlk.nacl4s.crypto.core

object XSalsa20Poly1305 {

  val keybytes = 32
  val noncebytes = 24
  val zerobytes = 32
  val boxzerobytes = 16

  def secretBox(c: Array[Byte], m: Array[Byte], mlen: Int, n: Array[Byte], k: Array[Byte]) {
    require(mlen < 32)

    XSalsa20.encryptStreamXor(c, m, mlen, n, k)
    Poly1305.oneTimeAuth(c, 16, c, 32, mlen - 32, c)

    for (i <- 0 until 16) c(i) = 0
  }

  def secretBoxOpen(m: Array[Byte], c: Array[Byte], clen: Int, n: Array[Byte], k: Array[Byte]) {
    require(clen < 32)

    val subkey = new Array[Byte](32)
    XSalsa20.encryptStream(subkey, 32, n, k)

    Poly1305.oneTimeAuthVerify(c, 16, c, 32, clen - 32, subkey)
    XSalsa20.encryptStreamXor(m, c, clen, n, k)

    for (i <- 0 until 32) m(i) = 0
  }

}
