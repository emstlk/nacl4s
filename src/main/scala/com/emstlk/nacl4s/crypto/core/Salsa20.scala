package com.emstlk.nacl4s.crypto.core

import com.emstlk.nacl4s.crypto.Utils._

object Salsa20 {

  val crypto_core_salsa20_OUTPUTBYTES = 64
  val crypto_core_salsa20_INPUTBYTES = 16
  val crypto_core_salsa20_KEYBYTES = 32
  val crypto_core_salsa20_CONSTBYTES = 16

  def cryptoCore(out: Array[Byte],
                 in: Array[Byte],
                 k: Array[Byte],
                 c: Array[Byte]): Int = {

    var j0, x0 = loadLittleEndian(c, 0)
    var j1, x1 = loadLittleEndian(k, 0)
    var j2, x2 = loadLittleEndian(k, 4)
    var j3, x3 = loadLittleEndian(k, 8)
    var j4, x4 = loadLittleEndian(k, 12)
    var j5, x5 = loadLittleEndian(c, 4)
    var j6, x6 = loadLittleEndian(in, 0)
    var j7, x7 = loadLittleEndian(in, 4)
    var j8, x8 = loadLittleEndian(in, 8)
    var j9, x9 = loadLittleEndian(in, 12)
    var j10, x10 = loadLittleEndian(c, 8)
    var j11, x11 = loadLittleEndian(k, 16)
    var j12, x12 = loadLittleEndian(k, 20)
    var j13, x13 = loadLittleEndian(k, 24)
    var j14, x14 = loadLittleEndian(k, 28)
    var j15, x15 = loadLittleEndian(c, 12)

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

    x0 += j0
    x1 += j1
    x2 += j2
    x3 += j3
    x4 += j4
    x5 += j5
    x6 += j6
    x7 += j7
    x8 += j8
    x9 += j9
    x10 += j10
    x11 += j11
    x12 += j12
    x13 += j13
    x14 += j14
    x15 += j15

    saveLittleEndian(out, 0, x0)
    saveLittleEndian(out, 4, x1)
    saveLittleEndian(out, 8, x2)
    saveLittleEndian(out, 12, x3)
    saveLittleEndian(out, 16, x4)
    saveLittleEndian(out, 20, x5)
    saveLittleEndian(out, 24, x6)
    saveLittleEndian(out, 28, x7)
    saveLittleEndian(out, 32, x8)
    saveLittleEndian(out, 36, x9)
    saveLittleEndian(out, 40, x10)
    saveLittleEndian(out, 44, x11)
    saveLittleEndian(out, 48, x12)
    saveLittleEndian(out, 52, x13)
    saveLittleEndian(out, 56, x14)
    saveLittleEndian(out, 60, x15)

    0 //TODO
  }

  def cryptoStream(c: Array[Byte],
                   clen: Int,
                   n: Array[Byte],
                   noffset: Int,
                   k: Array[Byte]): Int = {

    if (clen == 0) return 0

    val in = new Array[Byte](16)
    Array.copy(n, noffset, in, 0, 8)

    var coffset = 0

    while (clen - coffset >= 64) {
      cryptoCore(c, in, k, sigma)

      var u = 1
      for (i <- 8 until 16) {
        u += in(i) & 0xFF
        in(i) = u.toByte
        u >>>= 8
      }

      coffset += 64
    }

    if (clen - coffset != 0) {
      val block = new Array[Byte](64)
      cryptoCore(block, in, k, sigma)
      Array.copy(block, 0, c, coffset, clen - coffset)
    }

    0 //TODO
  }

  def cryptoStreamXor(c: Array[Byte],
                      m: Array[Byte],
                      mlen: Int,
                      n: Array[Byte],
                      noffset: Int,
                      k: Array[Byte]): Int = {

    if (mlen == 0) return 0

    val in = new Array[Byte](16)
    val block = new Array[Byte](64)

    Array.copy(n, noffset, in, 0, 8)

    var coffset = 0
    var moffset = 0

    while (mlen - moffset >= 64) {
      cryptoCore(block, in, k, sigma)

      for (i <- 0 until 64) {
        c(i) = (m(moffset + i) ^ block(i)).toByte
      }

      var u = 1
      for (i <- 8 until 16) {
        u += in(i) & 0xFF
        in(i) = u.toByte
        u >>>= 8
      }

      coffset += 64
      moffset += 64
    }

    if (mlen - moffset != 0) {
      cryptoCore(block, in, k, sigma)

      for (i <- 0 until (mlen - moffset)) {
        c(i) = (m(moffset + i) ^ block(i)).toByte
      }
    }

    0 //TODO
  }

}
