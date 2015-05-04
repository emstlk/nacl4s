package com.emstlk.nacl4s.crypto.core

object Verify16 {

  val bytes = 16

  def cryptoVerify(x: Array[Byte], xoffset: Int, y: Array[Byte]) {
    var differentbits = 0
    for (i <- 0 to 15) {
      differentbits |= x(xoffset + i) ^ y(i)
    }

    val result = (1 & ((differentbits - 1) >>> 8)) - 1
    if (result != 0) sys.error("signature was forged or corrupted")
  }
}
