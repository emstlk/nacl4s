package com.emstlk.nacl4s.crypto.verify

object Verify16 {

  val bytes = 16

  def cryptoVerify(x: Array[Byte], xOffset: Int, y: Array[Byte]) {
    var differentBits = 0
    for (i <- 0 until bytes) {
      differentBits |= x(xOffset + i) ^ y(i)
    }

    val result = (1 & (((differentBits & 0xff) - 1) >>> 8)) - 1
    if (result != 0) sys.error("signature was forged or corrupted")
  }
}
