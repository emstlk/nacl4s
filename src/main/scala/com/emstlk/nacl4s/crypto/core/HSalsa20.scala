package com.emstlk.nacl4s.crypto.core

import com.emstlk.nacl4s.crypto.Utils._

object HSalsa20 {

  val crypto_core_hsalsa20_OUTPUTBYTES = 32
  val crypto_core_hsalsa20_INPUTBYTES = 16
  val crypto_core_hsalsa20_KEYBYTES = 32
  val crypto_core_hsalsa20_CONSTBYTES = 16

  def cryptoCore(out: Array[Byte],
                 in: Array[Byte],
                 k: Array[Byte],
                 c: Array[Byte]): Int = {

    var x0 = loadLittleEndian(c, 0)
    var x1 = loadLittleEndian(k, 0)
    var x2 = loadLittleEndian(k, 4)
    var x3 = loadLittleEndian(k, 8)
    var x4 = loadLittleEndian(k, 12)
    var x5 = loadLittleEndian(c, 4)
    var x6 = loadLittleEndian(in, 0)
    var x7 = loadLittleEndian(in, 4)
    var x8 = loadLittleEndian(in, 8)
    var x9 = loadLittleEndian(in, 12)
    var x10 = loadLittleEndian(c, 8)
    var x11 = loadLittleEndian(k, 16)
    var x12 = loadLittleEndian(k, 20)
    var x13 = loadLittleEndian(k, 24)
    var x14 = loadLittleEndian(k, 28)
    var x15 = loadLittleEndian(c, 12)

    for (i <- 20 until 0 by -2) {
      x4 ^= rotate(x0 + x12, 7)
      x8 ^= rotate(x4 + x0, 9)
      x12 ^= rotate(x8 + x4, 13)
      x0 ^= rotate(x12 + x8, 18)
      x9 ^= rotate(x5 + x1, 7)
      x13 ^= rotate(x9 + x5, 9)
      x1 ^= rotate(x13 + x9, 13)
      x5 ^= rotate(x1 + x13, 18)
      x14 ^= rotate(x10 + x6, 7)
      x2 ^= rotate(x14 + x10, 9)
      x6 ^= rotate(x2 + x14, 13)
      x10 ^= rotate(x6 + x2, 18)
      x3 ^= rotate(x15 + x11, 7)
      x7 ^= rotate(x3 + x15, 9)
      x11 ^= rotate(x7 + x3, 13)
      x15 ^= rotate(x11 + x7, 18)
      x1 ^= rotate(x0 + x3, 7)
      x2 ^= rotate(x1 + x0, 9)
      x3 ^= rotate(x2 + x1, 13)
      x0 ^= rotate(x3 + x2, 18)
      x6 ^= rotate(x5 + x4, 7)
      x7 ^= rotate(x6 + x5, 9)
      x4 ^= rotate(x7 + x6, 13)
      x5 ^= rotate(x4 + x7, 18)
      x11 ^= rotate(x10 + x9, 7)
      x8 ^= rotate(x11 + x10, 9)
      x9 ^= rotate(x8 + x11, 13)
      x10 ^= rotate(x9 + x8, 18)
      x12 ^= rotate(x15 + x14, 7)
      x13 ^= rotate(x12 + x15, 9)
      x14 ^= rotate(x13 + x12, 13)
      x15 ^= rotate(x14 + x13, 18)
    }

    saveLittleEndian(out, 0, x0)
    saveLittleEndian(out, 4, x5)
    saveLittleEndian(out, 8, x10)
    saveLittleEndian(out, 12, x15)
    saveLittleEndian(out, 16, x6)
    saveLittleEndian(out, 20, x7)
    saveLittleEndian(out, 24, x8)
    saveLittleEndian(out, 28, x9)

    0 //TODO
  }

}