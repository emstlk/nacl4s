package com.emstlk.nacl4s.crypto.core

object Verify16 {

  val crypto_verify_16_BYTES = 16

  def cryptoVerify(x: Array[Byte], xoffset: Int, y: Array[Byte]): Int = {
    var differentbits = 0
    for (i <- 0 to 15) {
      differentbits |= x(xoffset + i) ^ y(i)
    }

    (1 & ((differentbits - 1) >>> 8)) - 1
  }
}
