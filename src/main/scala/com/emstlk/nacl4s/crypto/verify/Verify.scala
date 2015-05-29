package com.emstlk.nacl4s.crypto.verify

object Verify {

  private def verify(x: Array[Byte], xOffset: Int, y: Array[Byte], count: Int): Boolean = {
    var differentBits = 0
    var i = 0
    while (i < count) {
      differentBits |= x(xOffset + i) ^ y(i)
      i += 1
    }

    0 == (1 & (((differentBits & 0xff) - 1) >>> 8)) - 1
  }

  def cryptoVerify16(x: Array[Byte], xOffset: Int, y: Array[Byte]) = verify(x, xOffset, y, 16)

  def cryptoVerify32(x: Array[Byte], xOffset: Int, y: Array[Byte]) = verify(x, xOffset, y, 32)

}
