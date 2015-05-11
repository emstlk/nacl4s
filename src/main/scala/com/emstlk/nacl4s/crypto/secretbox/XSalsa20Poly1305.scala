package com.emstlk.nacl4s.crypto.secretbox

import com.emstlk.nacl4s.crypto.onetimeauth.Poly1305
import com.emstlk.nacl4s.crypto.stream.XSalsa20

object XSalsa20Poly1305 {

  val keyBytes = 32
  val nonceBytes = 24
  val zeroBytes = 32
  val boxZeroBytes = 16

  def cryptoSecretBox(c: Array[Byte], m: Array[Byte], mlen: Int, n: Array[Byte], k: Array[Byte]) {
    require(mlen >= zeroBytes)

    XSalsa20.cryptoStreamXor(c, m, mlen, n, k)
    Poly1305.cryptoOneTimeAuth(c, boxZeroBytes, c, zeroBytes, mlen - zeroBytes, c)

    for (i <- 0 until boxZeroBytes) c(i) = 0
  }

  def cryptoSecretBoxOpen(m: Array[Byte], c: Array[Byte], clen: Int, n: Array[Byte], k: Array[Byte]) {
    require(clen >= zeroBytes)

    val subkey = new Array[Byte](keyBytes)
    XSalsa20.cryptoStream(subkey, keyBytes, n, k)

    Poly1305.cryptoOneTimeAuthVerify(c, boxZeroBytes, c, zeroBytes, clen - zeroBytes, subkey)
    XSalsa20.cryptoStreamXor(m, c, clen, n, k)

    for (i <- 0 until zeroBytes) m(i) = 0
  }

}
