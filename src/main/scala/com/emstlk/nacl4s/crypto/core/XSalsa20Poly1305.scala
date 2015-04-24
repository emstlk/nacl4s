package com.emstlk.nacl4s.crypto.core

object XSalsa20Poly1305 {

  val crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32
  val crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24
  val crypto_secretbox_xsalsa20poly1305_ZEROBYTES = 32
  val crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16

  def cryptoSecretBox(c: Array[Byte],
                      m: Array[Byte],
                      mlen: Int,
                      n: Array[Byte],
                      k: Array[Byte]): Int = {
    if (mlen < 32) return -1

    XSalsa20.cryptoStreamXor(c, m, mlen, n, k)
    Poly1305.cryptoOnetimeauth(c, 16, c, 32, mlen - 32, c)

    for (i <- 0 until 16) {
      c(i) = 0
    }
    0
  }

  def cryptoSecretBoxOpen(m: Array[Byte],
                          c: Array[Byte],
                          clen: Int,
                          n: Array[Byte],
                          k: Array[Byte]): Int = {
    if (clen < 32) return -1

    val subkey = new Array[Byte](32)
    XSalsa20.cryptoStream(subkey, 32, n, k)

    if (Poly1305.cryptoOnetimeauthVerify(c, 16, c, 32, clen - 32, subkey) != 0) return -1
    XSalsa20.cryptoStreamXor(m, c, clen, n, k)

    for (i <- 0 until 32) {
      m(i) = 0
    }
    0
  }

}
