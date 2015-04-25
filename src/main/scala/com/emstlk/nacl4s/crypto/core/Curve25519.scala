package com.emstlk.nacl4s.crypto.core

object Curve25519 {

  val crypto_scalarmult_curve25519_BYTES = 32
  val crypto_scalarmult_curve25519_SCALARBYTES = 32

  def fsum(out: Array[Long], in: Array[Long]) {
    for (i <- 0 until 5) {
      out(i) += in(i)
    }
  }

  def fdifference_backwards(out: Array[Long], in: Array[Long]) {
    val two54m152 = (1L << 54) - 152
    val two54m8 = (1L << 54) - 8

    out(0) = in(0) + two54m152 - out(0)
    for (i <- 1 to 4) {
      out(i) = in(i) + two54m8 - out(i)
    }
  }

  def fscalar_product(out: Array[Long], in: Array[Long], scalar: Long) {
    var a = BigInt(in(0)) * scalar
    out(0) = a.toLong & 0x7ffffffffffffL

    a = BigInt(in(1)) * scalar + (a >> 51).toLong
    out(1) = a.toLong & 0x7ffffffffffffL

    a = BigInt(in(2)) * scalar + (a >> 51).toLong
    out(2) = a.toLong & 0x7ffffffffffffL

    a = BigInt(in(3)) * scalar + (a >> 51).toLong
    out(3) = a.toLong & 0x7ffffffffffffL

    a = BigInt(in(4)) * scalar + (a >> 51).toLong
    out(4) = a.toLong & 0x7ffffffffffffL

    out(0) += ((a >> 51) * 19).toLong
  }

  def fmul(out: Array[Long], in2: Array[Long], in: Array[Long]) {
    val t = new Array[BigInt](5)

    var r0 = BigInt(in(0))
    var r1 = BigInt(in(1))
    var r2 = BigInt(in(2))
    var r3 = BigInt(in(3))
    var r4 = BigInt(in(4))

    val s0 = in2(0)
    val s1 = in2(1)
    val s2 = in2(2)
    val s3 = in2(3)
    val s4 = in2(4)

    t(0) = r0 * s0
    t(1) = r0 * s1 + r1 * s0
    t(2) = r0 * s2 + r2 * s0 + r1 * s1
    t(3) = r0 * s3 + r3 * s0 + r1 * s2 + r2 * s1
    t(4) = r0 * s4 + r4 * s0 + r3 * s1 + r1 * s3 + r2 * s2

    r1 *= 19
    r2 *= 19
    r3 *= 19
    r4 *= 19

    t(0) += r4 * s1 + r1 * s4 + r2 * s3 + r3 * s2
    t(1) += r4 * s2 + r2 * s4 + r3 * s3
    t(2) += r4 * s3 + r3 * s4
    t(3) += r4 * s4

    r0 = t(0) & 0x7ffffffffffffL
    t(1) += t(0) >> 51 & 0xffffffffffffffffL

    r1 = t(1) & 0x7ffffffffffffL
    t(2) += t(1) >> 51 & 0xffffffffffffffffL

    r2 = t(2) & 0x7ffffffffffffL
    t(3) += t(2) >> 51 & 0xffffffffffffffffL

    r3 = t(3) & 0x7ffffffffffffL
    t(4) += t(3) >> 51 & 0xffffffffffffffffL

    r4 = t(4) & 0x7ffffffffffffL

    var c = t(4) >> 51 & 0xffffffffffffffffL

    r0 += c * 19
    c = r0 >> 51
    r0 = r0 & 0x7ffffffffffffL

    r1 += c
    c = r1 >> 51
    r1 = r1 & 0x7ffffffffffffL

    r2 += c

    out(0) = r0.toLong
    out(1) = r1.toLong
    out(2) = r2.toLong
    out(3) = r3.toLong
    out(4) = r4.toLong
  }

  def fsquare_times(out: Array[Long], in: Array[Long], count: Int) {
    val t = new Array[BigInt](5)

    var r0 = BigInt(in(0))
    var r1 = BigInt(in(1))
    var r2 = BigInt(in(2))
    var r3 = BigInt(in(3))
    var r4 = BigInt(in(4))

    for (_ <- 1 to count) {
      val d0 = r0 * 2
      val d1 = r1 * 2
      val d2 = r2 * 2 * 19
      val d419 = r4 * 19
      val d4 = d419 * 2

      t(0) = r0 * r0 + d4 * r1 + d2 * r3
      t(1) = d0 * r1 + d4 * r2 + r3 * r3 * 19
      t(2) = d0 * r2 + r1 * r1 + d4 * r3
      t(3) = d0 * r3 + d1 * r2 + r4 * d419
      t(4) = d0 * r4 + d1 * r3 + r2 * r2

      r0 = t(0) & 0x7ffffffffffffL
      t(1) += t(0) >> 51 & 0xffffffffffffffffL

      r1 = t(1) & 0x7ffffffffffffL
      t(2) += t(1) >> 51 & 0xffffffffffffffffL

      r2 = t(2) & 0x7ffffffffffffL
      t(3) += t(2) >> 51 & 0xffffffffffffffffL

      r3 = t(3) & 0x7ffffffffffffL
      t(4) += t(3) >> 51 & 0xffffffffffffffffL

      r4 = t(4) & 0x7ffffffffffffL

      var c = t(4) >> 51 & 0xffffffffffffffffL

      r0 = r0 + c * 19
      c = r0 >> 51
      r0 = r0 & 0x7ffffffffffffL

      r1 += c
      c = r1 >> 51
      r1 = r1 & 0x7ffffffffffffL

      r2 += c
    }

    out(0) = r0.toLong
    out(1) = r1.toLong
    out(2) = r2.toLong
    out(3) = r3.toLong
    out(4) = r4.toLong
  }

  def load_limb(in: Array[Byte], offset: Int): Long = {
    (in(offset).toLong & 0xff) |
      ((in(offset + 1).toLong & 0xff) << 8) |
      ((in(offset + 2).toLong & 0xff) << 16) |
      ((in(offset + 3).toLong & 0xff) << 24) |
      ((in(offset + 4).toLong & 0xff) << 32) |
      ((in(offset + 5).toLong & 0xff) << 40) |
      ((in(offset + 6).toLong & 0xff) << 48) |
      ((in(offset + 7).toLong & 0xff) << 56)
  }

  def store_limb(out: Array[Byte], offset: Int, in: Long) {
    out(offset) = (in & 0xFF).toByte
    out(offset + 1) = ((in >>> 8) & 0xFF).toByte
    out(offset + 2) = ((in >>> 16) & 0xFF).toByte
    out(offset + 3) = ((in >>> 24) & 0xFF).toByte
    out(offset + 4) = ((in >>> 32) & 0xFF).toByte
    out(offset + 5) = ((in >>> 40) & 0xFF).toByte
    out(offset + 6) = ((in >>> 48) & 0xFF).toByte
    out(offset + 7) = ((in >>> 56) & 0xFF).toByte
  }

  def fexpand(out: Array[Long], in: Array[Byte]) {
    out(0) = load_limb(in, 0) & 0x7ffffffffffffL
    out(1) = (load_limb(in, 6) >>> 3) & 0x7ffffffffffffL
    out(2) = (load_limb(in, 12) >>> 6) & 0x7ffffffffffffL
    out(3) = (load_limb(in, 19) >>> 1) & 0x7ffffffffffffL
    out(4) = (load_limb(in, 24) >>> 12) & 0x7ffffffffffffL
  }

  def fcontract(out: Array[Byte], in: Array[Long]) {
    val t = new Array[BigInt](5)

    t(0) = in(0)
    t(1) = in(1)
    t(2) = in(2)
    t(3) = in(3)
    t(4) = in(4)

    @inline def doReduce() {
      t(1) += t(0) >> 51
      t(0) &= 0x7ffffffffffffL

      t(2) += t(1) >> 51
      t(1) &= 0x7ffffffffffffL

      t(3) += t(2) >> 51
      t(2) &= 0x7ffffffffffffL

      t(4) += t(3) >> 51
      t(3) &= 0x7ffffffffffffL

      t(0) += 19 * (t(4) >> 51)
      t(4) &= 0x7ffffffffffffL
    }

    doReduce()
    doReduce()

    t(0) += 19

    doReduce()

    t(0) += 0x8000000000000L - 19
    t(1) += 0x8000000000000L - 1
    t(2) += 0x8000000000000L - 1
    t(3) += 0x8000000000000L - 1
    t(4) += 0x8000000000000L - 1

    t(1) += t(0) >> 51
    t(0) &= 0x7ffffffffffffL

    t(2) += t(1) >> 51
    t(1) &= 0x7ffffffffffffL

    t(3) += t(2) >> 51
    t(2) &= 0x7ffffffffffffL

    t(4) += t(3) >> 51
    t(3) &= 0x7ffffffffffffL

    t(4) &= 0x7ffffffffffffL

    store_limb(out, 0, (t(0) | (t(1) << 51)).toLong)
    store_limb(out, 8, ((t(1) >> 13) | (t(2) << 38)).toLong)
    store_limb(out, 16, ((t(2) >> 26) | (t(3) << 25)).toLong)
    store_limb(out, 24, ((t(3) >> 39) | (t(4) << 12)).toLong)
  }

  def fmonty(x2: Array[Long],
             z2: Array[Long],
             x3: Array[Long],
             z3: Array[Long],
             x: Array[Long],
             z: Array[Long],
             xprime: Array[Long],
             zprime: Array[Long],
             qmqp: Array[Long]) {
    val origx = new Array[Long](5)
    Array.copy(x, 0, origx, 0, 5)
    fsum(x, z)
    fdifference_backwards(z, origx)

    val origxprime = new Array[Long](5)
    Array.copy(xprime, 0, origxprime, 0, 5)
    fsum(xprime, zprime)
    fdifference_backwards(zprime, origxprime)
    val xxprime = new Array[Long](5)
    fmul(xxprime, xprime, z)
    val zzprime = new Array[Long](5)
    fmul(zzprime, x, zprime)
    Array.copy(xxprime, 0, origxprime, 0, 5)
    fsum(xxprime, zzprime)
    fdifference_backwards(zzprime, origxprime)
    fsquare_times(x3, xxprime, 1)

    val zzzprime = new Array[Long](5)
    fsquare_times(zzzprime, zzprime, 1)
    fmul(z3, zzzprime, qmqp)

    val xx = new Array[Long](5)
    fsquare_times(xx, x, 1)
    val zz = new Array[Long](5)
    fsquare_times(zz, z, 1)
    fmul(x2, xx, zz)
    fdifference_backwards(zz, xx)
    val zzz = new Array[Long](5)
    fscalar_product(zzz, zz, 121665)

    fsum(zzz, xx)
    fmul(z2, zz, zzz)
  }

  def swap_conditional(a: Array[Long], b: Array[Long], iswap: Long) {
    for (i <- 0 until 5) {
      val x = -iswap & (a(i) ^ b(i))
      a(i) ^= x
      b(i) ^= x
    }
  }

  def cmult(resultx: Array[Long], resultz: Array[Long], n: Array[Byte], q: Array[Long]) {
    var nqpqx = new Array[Long](5)
    Array.copy(q, 0, nqpqx, 0, 5)
    var nqpqz = new Array[Long](5)
    nqpqz(0) = 1

    var nqx = new Array[Long](5)
    nqx(0) = 1
    var nqz = new Array[Long](5)

    var nqx2 = new Array[Long](5)
    var nqz2 = new Array[Long](5)
    nqz2(0) = 1

    var nqpqx2 = new Array[Long](5)
    var nqpqz2 = new Array[Long](5)
    nqpqz2(0) = 1

    for (i <- 0 until 32) {
      var byte = n(31 - i)

      for (j <- 0 until 8) {
        val bit: Long = byte >>> 7 & 1

        swap_conditional(nqx, nqpqx, bit)
        swap_conditional(nqz, nqpqz, bit)
        fmonty(nqx2, nqz2, nqpqx2, nqpqz2, nqx, nqz, nqpqx, nqpqz, q)
        swap_conditional(nqx2, nqpqx2, bit)
        swap_conditional(nqz2, nqpqz2, bit)

        var t = nqx
        nqx = nqx2
        nqx2 = t

        t = nqz
        nqz = nqz2
        nqz2 = t

        t = nqpqx
        nqpqx = nqpqx2
        nqpqx2 = t

        t = nqpqz
        nqpqz = nqpqz2
        nqpqz2 = t

        byte = (byte << 1).toByte
      }
    }

    Array.copy(nqx, 0, resultx, 0, 5)
    Array.copy(nqz, 0, resultz, 0, 5)
  }

  def crecip(out: Array[Long], z: Array[Long]) {
    val a = new Array[Long](5)
    val t0 = new Array[Long](5)
    val b = new Array[Long](5)
    val c = new Array[Long](5)

    fsquare_times(a, z, 1)
    fsquare_times(t0, a, 2)
    fmul(b, t0, z)
    fmul(a, b, a)
    fsquare_times(t0, a, 1)
    fmul(b, t0, b)
    fsquare_times(t0, b, 5)
    fmul(b, t0, b)
    fsquare_times(t0, b, 10)
    fmul(c, t0, b)
    fsquare_times(t0, c, 20)
    fmul(t0, t0, c)
    fsquare_times(t0, t0, 10)
    fmul(b, t0, b)
    fsquare_times(t0, b, 50)
    fmul(c, t0, b)
    fsquare_times(t0, c, 100)
    fmul(t0, t0, c)
    fsquare_times(t0, t0, 50)
    fmul(t0, t0, b)
    fsquare_times(t0, t0, 5)
    fmul(out, t0, a)
  }

  def crypto_scalarmult(public: Array[Byte], secret: Array[Byte], basepoint: Array[Byte]): Int = {
    val e = new Array[Byte](32)

    for (i <- 0 until 32) {
      e(i) = secret(i)
    }

    e(0) = (e(0) & 248).toByte
    e(31) = (e(31) & 127).toByte
    e(31) = (e(31) | 64).toByte

    val bp = new Array[Long](5)
    fexpand(bp, basepoint)

    val x = new Array[Long](5)
    val z = new Array[Long](5)
    cmult(x, z, e, bp)

    val zmone = new Array[Long](5)
    crecip(zmone, z)
    fmul(z, x, zmone)
    fcontract(public, z)

    0
  }

  val basepoint = {
    val bp = new Array[Byte](32)
    bp(0) = 9
    bp
  }

  def crypto_scalarmult_base(q: Array[Byte], n: Array[Byte]) = crypto_scalarmult(q, n, basepoint)

}
