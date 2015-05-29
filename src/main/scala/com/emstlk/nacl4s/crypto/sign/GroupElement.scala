package com.emstlk.nacl4s.crypto.sign

import scala.util.control.Breaks._

object GroupElement {

  @inline def equal(b: Byte, c: Byte): Byte =
    (((b ^ c) - 1) >>> 31).toByte

  @inline def negative(b: Byte): Byte =
    (b.toLong >>> 63).toByte

  @inline def cmov(t: Precomp, u: Precomp, b: Int) {
    FieldElement.cmov(t.yplusx, u.yplusx, b)
    FieldElement.cmov(t.yminusx, u.yminusx, b)
    FieldElement.cmov(t.xy2d, u.xy2d, b)
  }

  /** r = 2 * p */
  def p2Dbl(r: P1p1, p: P2) {
    val t0 = new Array[Int](10)
    FieldElement.sq(r.x, p.x, false)
    FieldElement.sq(r.z, p.y, false)
    FieldElement.sq(r.t, p.z, true)
    FieldElement.add(r.y, p.x, p.y)
    FieldElement.sq(t0, r.y, false)
    FieldElement.add(r.y, r.z, r.x)
    FieldElement.sub(r.z, r.z, r.x)
    FieldElement.sub(r.x, t0, r.y)
    FieldElement.sub(r.t, r.t, r.z)
  }

  /** r = 2 * p */
  def p3Dbl(r: P1p1, p: P3) {
    val q = new P2
    Array.copy(p.x, 0, q.x, 0, 10)
    Array.copy(p.y, 0, q.y, 0, 10)
    Array.copy(p.z, 0, q.z, 0, 10)
    p2Dbl(r, q)
  }

  def select(t: Precomp, pos: Int, b: Byte) {
    val bNegative = negative(b)
    val babs = (b - (((-bNegative) & b) << 1)).toByte

    t.yplusx(0) = 1
    t.yminusx(0) = 1
    t.xy2d(0) = 0
    var i = 1
    while (i <= 9) {
      t.yplusx(i) = 0
      t.yminusx(i) = 0
      t.xy2d(i) = 0
      i += 1
    }

    cmov(t, Const.base(pos)(0), equal(babs, 1))
    cmov(t, Const.base(pos)(1), equal(babs, 2))
    cmov(t, Const.base(pos)(2), equal(babs, 3))
    cmov(t, Const.base(pos)(3), equal(babs, 4))
    cmov(t, Const.base(pos)(4), equal(babs, 5))
    cmov(t, Const.base(pos)(5), equal(babs, 6))
    cmov(t, Const.base(pos)(6), equal(babs, 7))
    cmov(t, Const.base(pos)(7), equal(babs, 8))

    val minust = new Precomp
    Array.copy(t.yminusx, 0, minust.yplusx, 0, 10)
    Array.copy(t.yplusx, 0, minust.yminusx, 0, 10)
    i = 0
    while (i <= 9) {
      minust.xy2d(i) = -t.xy2d(i)
      i += 1
    }
    cmov(t, minust, bNegative)
  }

  /** r = p + q */
  def add(r: P1p1, p: P3, q: Cached) {
    val t0 = new Array[Int](10)
    FieldElement.add(r.x, p.y, p.x)
    FieldElement.sub(r.y, p.y, p.x)
    FieldElement.mul(r.z, r.x, q.yplusx)
    FieldElement.mul(r.y, r.y, q.yminusx)
    FieldElement.mul(r.t, q.t2d, p.t)
    FieldElement.mul(r.x, p.z, q.z)
    FieldElement.add(t0, r.x, r.x)
    FieldElement.sub(r.x, r.z, r.y)
    FieldElement.add(r.y, r.z, r.y)
    FieldElement.add(r.z, t0, r.t)
    FieldElement.sub(r.t, t0, r.t)
  }

  /** r = p - q */
  def sub(r: P1p1, p: P3, q: Cached) {
    val t0 = new Array[Int](10)
    FieldElement.add(r.x, p.y, p.x)
    FieldElement.sub(r.y, p.y, p.x)
    FieldElement.mul(r.z, r.x, q.yminusx)
    FieldElement.mul(r.y, r.y, q.yplusx)
    FieldElement.mul(r.t, q.t2d, p.t)
    FieldElement.mul(r.x, p.z, q.z)
    FieldElement.add(t0, r.x, r.x)
    FieldElement.sub(r.x, r.z, r.y)
    FieldElement.add(r.y, r.z, r.y)
    FieldElement.sub(r.z, t0, r.t)
    FieldElement.add(r.t, t0, r.t)
  }

  /** r = p + q */
  def madd(r: P1p1, p: P3, q: Precomp) {
    val t0 = new Array[Int](10)
    FieldElement.add(r.x, p.y, p.x)
    FieldElement.sub(r.y, p.y, p.x)
    FieldElement.mul(r.z, r.x, q.yplusx)
    FieldElement.mul(r.y, r.y, q.yminusx)
    FieldElement.mul(r.t, q.xy2d, p.t)
    FieldElement.add(t0, p.z, p.z)
    FieldElement.sub(r.x, r.z, r.y)
    FieldElement.add(r.y, r.z, r.y)
    FieldElement.add(r.z, t0, r.t)
    FieldElement.sub(r.t, t0, r.t)
  }

  /** r = p - q */
  def msub(r: P1p1, p: P3, q: Precomp) {
    val t0 = new Array[Int](10)
    FieldElement.add(r.x, p.y, p.x)
    FieldElement.sub(r.y, p.y, p.x)
    FieldElement.mul(r.z, r.x, q.yminusx)
    FieldElement.mul(r.y, r.y, q.yplusx)
    FieldElement.mul(r.t, q.xy2d, p.t)
    FieldElement.add(t0, p.z, p.z)
    FieldElement.sub(r.x, r.z, r.y)
    FieldElement.add(r.y, r.z, r.y)
    FieldElement.sub(r.z, t0, r.t)
    FieldElement.add(r.t, t0, r.t)
  }

  /** r = p */
  def p1p1ToP2(r: P2, p: P1p1) {
    FieldElement.mul(r.x, p.x, p.t)
    FieldElement.mul(r.y, p.y, p.z)
    FieldElement.mul(r.z, p.z, p.t)
  }

  /** r = p */
  def p1p1ToP3(r: P3, p: P1p1) {
    FieldElement.mul(r.x, p.x, p.t)
    FieldElement.mul(r.y, p.y, p.z)
    FieldElement.mul(r.z, p.z, p.t)
    FieldElement.mul(r.t, p.x, p.y)
  }

  def p3ToCached(r: Cached, p: P3) {
    FieldElement.add(r.yplusx, p.y, p.x)
    FieldElement.sub(r.yminusx, p.y, p.x)
    Array.copy(p.z, 0, r.z, 0, 10)
    FieldElement.mul(r.t2d, p.t, Const.d2)
  }

  def p3ToBytes(s: Array[Byte], h: P3) {
    val recip = new Array[Int](10)
    val x = new Array[Int](10)
    val y = new Array[Int](10)

    FieldElement.invert(recip, h.z)
    FieldElement.mul(x, h.x, recip)
    FieldElement.mul(y, h.y, recip)
    FieldElement.toBytes(s, y)
    s(31) = (s(31) ^ (FieldElement.isNegative(x) << 7)).toByte
  }

  //TODO the same as p3ToBytes
  def toBytes(s: Array[Byte], h: P2) {
    val recip = new Array[Int](10)
    val x = new Array[Int](10)
    val y = new Array[Int](10)

    FieldElement.invert(recip, h.z)
    FieldElement.mul(x, h.x, recip)
    FieldElement.mul(y, h.y, recip)
    FieldElement.toBytes(s, y)
    s(31) = (s(31) ^ (FieldElement.isNegative(x) << 7)).toByte
  }

  def scalarmultBase(h: P3, a: Array[Byte]) {
    val e = new Array[Byte](64)

    var i = 0
    while (i < 32) {
      e(2 * i) = (a(i) & 15).toByte
      e(2 * i + 1) = ((a(i) >>> 4) & 15).toByte
      i += 1
    }

    var carry: Byte = 0
    i = 0
    while (i < 63) {
      e(i) = (e(i) + carry).toByte
      carry = ((e(i) + 8) >> 4).toByte
      e(i) = (e(i) - (carry << 4)).toByte
      i += 1
    }
    e(63) = (e(63) + carry).toByte

    h.y(0) = 1
    h.z(0) = 1

    val t = new Precomp
    val r = new P1p1

    i = 1
    while (i < 64) {
      select(t, i / 2, e(i))
      madd(r, h, t)
      p1p1ToP3(h, r)
      i += 2
    }

    val s = new P2
    p3Dbl(r, h)
    p1p1ToP2(s, r)
    p2Dbl(r, s)
    p1p1ToP2(s, r)
    p2Dbl(r, s)
    p1p1ToP2(s, r)
    p2Dbl(r, s)
    p1p1ToP3(h, r)

    i = 0
    while (i < 64) {
      select(t, i / 2, e(i))
      madd(r, h, t)
      p1p1ToP3(h, r)
      i += 2
    }
  }

  def fromBytesNegateVartime(h: P3, s: Array[Byte]) {
    FieldElement.fromBytes(h.y, s)

    h.z(0) = 1

    val u = new Array[Int](10)
    FieldElement.sq(u, h.y, false)
    val v = new Array[Int](10)
    FieldElement.mul(v, u, Const.d)
    FieldElement.sub(u, u, h.z)
    FieldElement.add(v, v, h.z)

    val v3 = new Array[Int](10)
    FieldElement.sq(v3, v, false)
    FieldElement.mul(v3, v3, v)
    FieldElement.sq(h.x, v3, false)
    FieldElement.mul(h.x, h.x, v)
    FieldElement.mul(h.x, h.x, u)

    FieldElement.pow22523(h.x, h.x)
    FieldElement.mul(h.x, h.x, v3)
    FieldElement.mul(h.x, h.x, u)

    val vxx = new Array[Int](10)
    FieldElement.sq(vxx, h.x, false)
    FieldElement.mul(vxx, vxx, v)
    val check = new Array[Int](10)
    FieldElement.sub(check, vxx, u)

    if (FieldElement.isNonZero(check)) {
      FieldElement.add(check, vxx, u)

      require(!FieldElement.isNonZero(check))
      FieldElement.mul(h.x, h.x, Const.sqrtm1)
    }

    if (FieldElement.isNegative(h.x) == ((s(31) & 0xff) >>> 7))
      FieldElement.neg(h.x, h.x)

    FieldElement.mul(h.t, h.x, h.y)
  }

  def slide(r: Array[Byte], a: Array[Byte], aOffset: Int) {
    var i = 0
    while (i < 256) {
      r(i) = (1 & (a(aOffset + (i >> 3)) >>> (i & 7))).toByte
      i += 1
    }

    i = 0
    while (i < 256) {
      if (r(i) != 0) {
        breakable {
          var b = 1
          while (b <= 6 && i + b < 256) {
            if (r(i + b) != 0) {
              if (r(i) + (r(i + b) << b) <= 15) {
                r(i) = (r(i) + (r(i + b) << b)).toByte
                r(i + b) = 0
              } else if (r(i) - (r(i + b) << b) >= -15) {
                r(i) = (r(i) - (r(i + b) << b)).toByte
                breakable {
                  var k = i + b
                  while (k < 256) {
                    if (r(k) == 0) {
                      r(k) = 1
                      break()
                    }
                    r(k) = 0
                    k += 1
                  }
                }
              } else break()
            }
            b += 1
          }
        }
      }
      i += 1
    }
  }

  def doubleScalarmultVartime(r: P2, a: Array[Byte], p: P3, b: Array[Byte], bOffset: Int) {
    val aSlide = new Array[Byte](256)
    val bSlide = new Array[Byte](256)
    slide(aSlide, a, 0)
    slide(bSlide, b, bOffset)

    val ai = Array(
      new Cached, new Cached, new Cached, new Cached,
      new Cached, new Cached, new Cached, new Cached
    )
    p3ToCached(ai(0), p)
    val t = new P1p1
    p3Dbl(t, p)
    val a2 = new P3
    p1p1ToP3(a2, t)

    val u = new P3
    add(t, a2, ai(0))
    p1p1ToP3(u, t)
    p3ToCached(ai(1), u)
    add(t, a2, ai(1))
    p1p1ToP3(u, t)
    p3ToCached(ai(2), u)
    add(t, a2, ai(2))
    p1p1ToP3(u, t)
    p3ToCached(ai(3), u)
    add(t, a2, ai(3))
    p1p1ToP3(u, t)
    p3ToCached(ai(4), u)
    add(t, a2, ai(4))
    p1p1ToP3(u, t)
    p3ToCached(ai(5), u)
    add(t, a2, ai(5))
    p1p1ToP3(u, t)
    p3ToCached(ai(6), u)
    add(t, a2, ai(6))
    p1p1ToP3(u, t)
    p3ToCached(ai(7), u)

    r.y(0) = 1
    r.z(0) = 1

    var i = 255
    breakable {
      while (i >= 0) {
        if (aSlide(i) != 0 || bSlide(i) != 0) break()
        i -= 1
      }
    }

    while (i >= 0) {
      p2Dbl(t, r)

      if (aSlide(i) > 0) {
        p1p1ToP3(u, t)
        add(t, u, ai(aSlide(i) / 2))
      } else if (aSlide(i) < 0) {
        p1p1ToP3(u, t)
        sub(t, u, ai(-aSlide(i) / 2))
      }

      if (bSlide(i) > 0) {
        p1p1ToP3(u, t)
        madd(t, u, Const.bi(bSlide(i) / 2))
      } else if (bSlide(i) < 0) {
        p1p1ToP3(u, t)
        msub(t, u, Const.bi(-bSlide(i) / 2))
      }

      p1p1ToP2(r, t)
      i -= 1
    }
  }

}

class Precomp(val yplusx: Array[Int] = new Array[Int](10),
              val yminusx: Array[Int] = new Array[Int](10),
              val xy2d: Array[Int] = new Array[Int](10))

class Cached(val yplusx: Array[Int] = new Array[Int](10),
             val yminusx: Array[Int] = new Array[Int](10),
             val z: Array[Int] = new Array[Int](10),
             val t2d: Array[Int] = new Array[Int](10))

class P2(val x: Array[Int] = new Array[Int](10),
         val y: Array[Int] = new Array[Int](10),
         val z: Array[Int] = new Array[Int](10))

class P3(val x: Array[Int] = new Array[Int](10),
         val y: Array[Int] = new Array[Int](10),
         val z: Array[Int] = new Array[Int](10),
         val t: Array[Int] = new Array[Int](10))

class P1p1(val x: Array[Int] = new Array[Int](10),
           val y: Array[Int] = new Array[Int](10),
           val z: Array[Int] = new Array[Int](10),
           val t: Array[Int] = new Array[Int](10))
