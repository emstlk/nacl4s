package com.emstlk.nacl4s.crypto.sign

import com.emstlk.nacl4s.crypto.sign.Scalar._
import com.emstlk.nacl4s.crypto.verify.Verify

object FieldElement {

  @inline def add(h: Array[Int], f: Array[Int], g: Array[Int]) {
    var i = 0
    while (i < 10) {
      h(i) = f(i) + g(i)
      i += 1
    }
  }

  @inline def sub(h: Array[Int], f: Array[Int], g: Array[Int]) {
    var i = 0
    while (i < 10) {
      h(i) = f(i) - g(i)
      i += 1
    }
  }

  @inline def neg(h: Array[Int], f: Array[Int]) {
    var i = 0
    while (i < 10) {
      h(i) = -f(i)
      i += 1
    }
  }

  def mul(h: Array[Int], f: Array[Int], g: Array[Int]) {
    val g1_19 = 19 * g(1)
    val g2_19 = 19 * g(2)
    val g3_19 = 19 * g(3)
    val g4_19 = 19 * g(4)
    val g5_19 = 19 * g(5)
    val g6_19 = 19 * g(6)
    val g7_19 = 19 * g(7)
    val g8_19 = 19 * g(8)
    val g9_19 = 19 * g(9)
    val f1_2 = 2 * f(1)
    val f3_2 = 2 * f(3)
    val f5_2 = 2 * f(5)
    val f7_2 = 2 * f(7)
    val f9_2 = 2 * f(9)
    val f0g0 = f(0) * g(0).toLong
    val f0g1 = f(0) * g(1).toLong
    val f0g2 = f(0) * g(2).toLong
    val f0g3 = f(0) * g(3).toLong
    val f0g4 = f(0) * g(4).toLong
    val f0g5 = f(0) * g(5).toLong
    val f0g6 = f(0) * g(6).toLong
    val f0g7 = f(0) * g(7).toLong
    val f0g8 = f(0) * g(8).toLong
    val f0g9 = f(0) * g(9).toLong
    val f1g0 = f(1) * g(0).toLong
    val f1g1_2 = f1_2 * g(1).toLong
    val f1g2 = f(1) * g(2).toLong
    val f1g3_2 = f1_2 * g(3).toLong
    val f1g4 = f(1) * g(4).toLong
    val f1g5_2 = f1_2 * g(5).toLong
    val f1g6 = f(1) * g(6).toLong
    val f1g7_2 = f1_2 * g(7).toLong
    val f1g8 = f(1) * g(8).toLong
    val f1g9_38 = f1_2 * g9_19.toLong
    val f2g0 = f(2) * g(0).toLong
    val f2g1 = f(2) * g(1).toLong
    val f2g2 = f(2) * g(2).toLong
    val f2g3 = f(2) * g(3).toLong
    val f2g4 = f(2) * g(4).toLong
    val f2g5 = f(2) * g(5).toLong
    val f2g6 = f(2) * g(6).toLong
    val f2g7 = f(2) * g(7).toLong
    val f2g8_19 = f(2) * g8_19.toLong
    val f2g9_19 = f(2) * g9_19.toLong
    val f3g0 = f(3) * g(0).toLong
    val f3g1_2 = f3_2 * g(1).toLong
    val f3g2 = f(3) * g(2).toLong
    val f3g3_2 = f3_2 * g(3).toLong
    val f3g4 = f(3) * g(4).toLong
    val f3g5_2 = f3_2 * g(5).toLong
    val f3g6 = f(3) * g(6).toLong
    val f3g7_38 = f3_2 * g7_19.toLong
    val f3g8_19 = f(3) * g8_19.toLong
    val f3g9_38 = f3_2 * g9_19.toLong
    val f4g0 = f(4) * g(0).toLong
    val f4g1 = f(4) * g(1).toLong
    val f4g2 = f(4) * g(2).toLong
    val f4g3 = f(4) * g(3).toLong
    val f4g4 = f(4) * g(4).toLong
    val f4g5 = f(4) * g(5).toLong
    val f4g6_19 = f(4) * g6_19.toLong
    val f4g7_19 = f(4) * g7_19.toLong
    val f4g8_19 = f(4) * g8_19.toLong
    val f4g9_19 = f(4) * g9_19.toLong
    val f5g0 = f(5) * g(0).toLong
    val f5g1_2 = f5_2 * g(1).toLong
    val f5g2 = f(5) * g(2).toLong
    val f5g3_2 = f5_2 * g(3).toLong
    val f5g4 = f(5) * g(4).toLong
    val f5g5_38 = f5_2 * g5_19.toLong
    val f5g6_19 = f(5) * g6_19.toLong
    val f5g7_38 = f5_2 * g7_19.toLong
    val f5g8_19 = f(5) * g8_19.toLong
    val f5g9_38 = f5_2 * g9_19.toLong
    val f6g0 = f(6) * g(0).toLong
    val f6g1 = f(6) * g(1).toLong
    val f6g2 = f(6) * g(2).toLong
    val f6g3 = f(6) * g(3).toLong
    val f6g4_19 = f(6) * g4_19.toLong
    val f6g5_19 = f(6) * g5_19.toLong
    val f6g6_19 = f(6) * g6_19.toLong
    val f6g7_19 = f(6) * g7_19.toLong
    val f6g8_19 = f(6) * g8_19.toLong
    val f6g9_19 = f(6) * g9_19.toLong
    val f7g0 = f(7) * g(0).toLong
    val f7g1_2 = f7_2 * g(1).toLong
    val f7g2 = f(7) * g(2).toLong
    val f7g3_38 = f7_2 * g3_19.toLong
    val f7g4_19 = f(7) * g4_19.toLong
    val f7g5_38 = f7_2 * g5_19.toLong
    val f7g6_19 = f(7) * g6_19.toLong
    val f7g7_38 = f7_2 * g7_19.toLong
    val f7g8_19 = f(7) * g8_19.toLong
    val f7g9_38 = f7_2 * g9_19.toLong
    val f8g0 = f(8) * g(0).toLong
    val f8g1 = f(8) * g(1).toLong
    val f8g2_19 = f(8) * g2_19.toLong
    val f8g3_19 = f(8) * g3_19.toLong
    val f8g4_19 = f(8) * g4_19.toLong
    val f8g5_19 = f(8) * g5_19.toLong
    val f8g6_19 = f(8) * g6_19.toLong
    val f8g7_19 = f(8) * g7_19.toLong
    val f8g8_19 = f(8) * g8_19.toLong
    val f8g9_19 = f(8) * g9_19.toLong
    val f9g0 = f(9) * g(0).toLong
    val f9g1_38 = f9_2 * g1_19.toLong
    val f9g2_19 = f(9) * g2_19.toLong
    val f9g3_38 = f9_2 * g3_19.toLong
    val f9g4_19 = f(9) * g4_19.toLong
    val f9g5_38 = f9_2 * g5_19.toLong
    val f9g6_19 = f(9) * g6_19.toLong
    val f9g7_38 = f9_2 * g7_19.toLong
    val f9g8_19 = f(9) * g8_19.toLong
    val f9g9_38 = f9_2 * g9_19.toLong

    var h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38
    var h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19
    var h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38
    var h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19
    var h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38
    var h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19
    var h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38
    var h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19
    var h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38
    var h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0

    var carry0 = (h0 + (1 << 25)) >> 26
    h1 += carry0
    h0 -= carry0 << 26
    var carry4 = (h4 + (1 << 25)) >> 26
    h5 += carry4
    h4 -= carry4 << 26

    val carry1 = (h1 + (1 << 24)) >> 25
    h2 += carry1
    h1 -= carry1 << 25
    val carry5 = (h5 + (1 << 24)) >> 25
    h6 += carry5
    h5 -= carry5 << 25

    val carry2 = (h2 + (1 << 25)) >> 26
    h3 += carry2
    h2 -= carry2 << 26
    val carry6 = (h6 + (1 << 25)) >> 26
    h7 += carry6
    h6 -= carry6 << 26

    val carry3 = (h3 + (1 << 24)) >> 25
    h4 += carry3
    h3 -= carry3 << 25
    val carry7 = (h7 + (1 << 24)) >> 25
    h8 += carry7
    h7 -= carry7 << 25

    carry4 = (h4 + (1 << 25)) >> 26
    h5 += carry4
    h4 -= carry4 << 26
    val carry8 = (h8 + (1 << 25)) >> 26
    h9 += carry8
    h8 -= carry8 << 26

    val carry9 = (h9 + (1 << 24)) >> 25
    h0 += carry9 * 19
    h9 -= carry9 << 25

    carry0 = (h0 + (1 << 25)) >> 26
    h1 += carry0
    h0 -= carry0 << 26

    h(0) = h0.toInt
    h(1) = h1.toInt
    h(2) = h2.toInt
    h(3) = h3.toInt
    h(4) = h4.toInt
    h(5) = h5.toInt
    h(6) = h6.toInt
    h(7) = h7.toInt
    h(8) = h8.toInt
    h(9) = h9.toInt
  }

  /** h = f * f or h = 2 * f * f if double is true */
  def sq(h: Array[Int], f: Array[Int], double: Boolean) {
    val f0_2 = 2 * f(0)
    val f1_2 = 2 * f(1)
    val f2_2 = 2 * f(2)
    val f3_2 = 2 * f(3)
    val f4_2 = 2 * f(4)
    val f5_2 = 2 * f(5)
    val f6_2 = 2 * f(6)
    val f7_2 = 2 * f(7)
    val f5_38 = 38 * f(5)
    val f6_19 = 19 * f(6)
    val f7_38 = 38 * f(7)
    val f8_19 = 19 * f(8)
    val f9_38 = 38 * f(9)
    val f0f0 = f(0) * f(0).toLong
    val f0f1_2 = f0_2 * f(1).toLong
    val f0f2_2 = f0_2 * f(2).toLong
    val f0f3_2 = f0_2 * f(3).toLong
    val f0f4_2 = f0_2 * f(4).toLong
    val f0f5_2 = f0_2 * f(5).toLong
    val f0f6_2 = f0_2 * f(6).toLong
    val f0f7_2 = f0_2 * f(7).toLong
    val f0f8_2 = f0_2 * f(8).toLong
    val f0f9_2 = f0_2 * f(9).toLong
    val f1f1_2 = f1_2 * f(1).toLong
    val f1f2_2 = f1_2 * f(2).toLong
    val f1f3_4 = f1_2 * f3_2.toLong
    val f1f4_2 = f1_2 * f(4).toLong
    val f1f5_4 = f1_2 * f5_2.toLong
    val f1f6_2 = f1_2 * f(6).toLong
    val f1f7_4 = f1_2 * f7_2.toLong
    val f1f8_2 = f1_2 * f(8).toLong
    val f1f9_76 = f1_2 * f9_38.toLong
    val f2f2 = f(2) * f(2).toLong
    val f2f3_2 = f2_2 * f(3).toLong
    val f2f4_2 = f2_2 * f(4).toLong
    val f2f5_2 = f2_2 * f(5).toLong
    val f2f6_2 = f2_2 * f(6).toLong
    val f2f7_2 = f2_2 * f(7).toLong
    val f2f8_38 = f2_2 * f8_19.toLong
    val f2f9_38 = f(2) * f9_38.toLong
    val f3f3_2 = f3_2 * f(3).toLong
    val f3f4_2 = f3_2 * f(4).toLong
    val f3f5_4 = f3_2 * f5_2.toLong
    val f3f6_2 = f3_2 * f(6).toLong
    val f3f7_76 = f3_2 * f7_38.toLong
    val f3f8_38 = f3_2 * f8_19.toLong
    val f3f9_76 = f3_2 * f9_38.toLong
    val f4f4 = f(4) * f(4).toLong
    val f4f5_2 = f4_2 * f(5).toLong
    val f4f6_38 = f4_2 * f6_19.toLong
    val f4f7_38 = f(4) * f7_38.toLong
    val f4f8_38 = f4_2 * f8_19.toLong
    val f4f9_38 = f(4) * f9_38.toLong
    val f5f5_38 = f(5) * f5_38.toLong
    val f5f6_38 = f5_2 * f6_19.toLong
    val f5f7_76 = f5_2 * f7_38.toLong
    val f5f8_38 = f5_2 * f8_19.toLong
    val f5f9_76 = f5_2 * f9_38.toLong
    val f6f6_19 = f(6) * f6_19.toLong
    val f6f7_38 = f(6) * f7_38.toLong
    val f6f8_38 = f6_2 * f8_19.toLong
    val f6f9_38 = f(6) * f9_38.toLong
    val f7f7_38 = f(7) * f7_38.toLong
    val f7f8_38 = f7_2 * f8_19.toLong
    val f7f9_76 = f7_2 * f9_38.toLong
    val f8f8_19 = f(8) * f8_19.toLong
    val f8f9_38 = f(8) * f9_38.toLong
    val f9f9_38 = f(9) * f9_38.toLong

    var h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38
    var h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38
    var h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19
    var h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38
    var h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38
    var h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38
    var h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19
    var h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38
    var h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38
    var h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2

    if (double) {
      h0 += h0
      h1 += h1
      h2 += h2
      h3 += h3
      h4 += h4
      h5 += h5
      h6 += h6
      h7 += h7
      h8 += h8
      h9 += h9
    }

    var carry0 = (h0 + (1 << 25)) >> 26
    h1 += carry0
    h0 -= carry0 << 26
    var carry4 = (h4 + (1 << 25)) >> 26
    h5 += carry4
    h4 -= carry4 << 26

    val carry1 = (h1 + (1 << 24)) >> 25
    h2 += carry1
    h1 -= carry1 << 25
    val carry5 = (h5 + (1 << 24)) >> 25
    h6 += carry5
    h5 -= carry5 << 25

    val carry2 = (h2 + (1 << 25)) >> 26
    h3 += carry2
    h2 -= carry2 << 26
    val carry6 = (h6 + (1 << 25)) >> 26
    h7 += carry6
    h6 -= carry6 << 26

    val carry3 = (h3 + (1 << 24)) >> 25
    h4 += carry3
    h3 -= carry3 << 25
    val carry7 = (h7 + (1 << 24)) >> 25
    h8 += carry7
    h7 -= carry7 << 25

    carry4 = (h4 + (1 << 25)) >> 26
    h5 += carry4
    h4 -= carry4 << 26
    val carry8 = (h8 + (1 << 25)) >> 26
    h9 += carry8
    h8 -= carry8 << 26

    val carry9 = (h9 + (1 << 24)) >> 25
    h0 += carry9 * 19
    h9 -= carry9 << 25

    carry0 = (h0 + (1 << 25)) >> 26
    h1 += carry0
    h0 -= carry0 << 26

    h(0) = h0.toInt
    h(1) = h1.toInt
    h(2) = h2.toInt
    h(3) = h3.toInt
    h(4) = h4.toInt
    h(5) = h5.toInt
    h(6) = h6.toInt
    h(7) = h7.toInt
    h(8) = h8.toInt
    h(9) = h9.toInt
  }

  @inline def cmov(f: Array[Int], g: Array[Int], b: Int) {
    val nb = -b
    var i = 0
    while (i <= 9) {
      f(i) = f(i) ^ ((f(i) ^ g(i)) & nb)
      i += 1
    }
  }

  def pow22523(out: Array[Int], z: Array[Int]) {
    val t0 = new Array[Int](10)
    val t1 = new Array[Int](10)
    val t2 = new Array[Int](10)

    sq(t0, z, false)
    sq(t1, t0, false)
    sq(t1, t1, false)

    mul(t1, z, t1)
    mul(t0, t0, t1)
    sq(t0, t0, false)

    mul(t0, t1, t0)
    sq(t1, t0, false)
    var i = 1
    while (i < 5) {
      sq(t1, t1, false)
      i += 1
    }

    mul(t0, t1, t0)
    sq(t1, t0, false)
    i = 1
    while (i < 10) {
      sq(t1, t1, false)
      i += 1
    }

    mul(t1, t1, t0)
    sq(t2, t1, false)
    i = 1
    while (i < 20) {
      sq(t2, t2, false)
      i += 1
    }

    mul(t1, t2, t1)
    sq(t1, t1, false)
    i = 1
    while (i < 10) {
      sq(t1, t1, false)
      i += 1
    }

    mul(t0, t1, t0)
    sq(t1, t0, false)
    i = 1
    while (i < 50) {
      sq(t1, t1, false)
      i += 1
    }

    mul(t1, t1, t0)
    sq(t2, t1, false)
    i = 1
    while (i < 100) {
      sq(t2, t2, false)
      i += 1
    }

    mul(t1, t2, t1)
    sq(t1, t1, false)
    i = 1
    while (i < 50) {
      sq(t1, t1, false)
      i += 1
    }

    mul(t0, t1, t0)
    sq(t0, t0, false)
    sq(t0, t0, false)

    mul(out, t0, z)
  }

  def invert(out: Array[Int], z: Array[Int]) {
    val t0 = new Array[Int](10)
    val t1 = new Array[Int](10)
    val t2 = new Array[Int](10)
    val t3 = new Array[Int](10)

    // pow225521
    sq(t0, z, false)
    sq(t1, t0, false)
    sq(t1, t1, false)

    mul(t1, z, t1)
    mul(t0, t0, t1)
    sq(t2, t0, false)

    mul(t1, t1, t2)
    sq(t2, t1, false)
    var i = 1
    while (i < 5) {
      sq(t2, t2, false)
      i += 1
    }

    mul(t1, t2, t1)
    sq(t2, t1, false)
    i = 1
    while (i < 10) {
      sq(t2, t2, false)
      i += 1
    }

    mul(t2, t2, t1)
    sq(t3, t2, false)
    i = 1
    while (i < 20) {
      sq(t3, t3, false)
      i += 1
    }

    mul(t2, t3, t2)
    sq(t2, t2, false)
    i = 1
    while (i < 10) {
      sq(t2, t2, false)
      i += 1
    }

    mul(t1, t2, t1)
    sq(t2, t1, false)
    i = 1
    while (i < 50) {
      sq(t2, t2, false)
      i += 1
    }

    mul(t2, t2, t1)
    sq(t3, t2, false)
    i = 1
    while (i < 100) {
      sq(t3, t3, false)
      i += 1
    }

    mul(t2, t3, t2)
    sq(t2, t2, false)
    i = 1
    while (i < 50) {
      sq(t2, t2, false)
      i += 1
    }

    mul(t1, t2, t1)
    sq(t1, t1, false)
    i = 1
    while (i < 5) {
      sq(t1, t1, false)
      i += 1
    }

    mul(out, t1, t0)
  }

  /* Ignores top bit of h */
  def fromBytes(h: Array[Int], s: Array[Byte]) {
    var h0 = load4(s, 0)
    var h1 = load3(s, 4) << 6
    var h2 = load3(s, 7) << 5
    var h3 = load3(s, 10) << 3
    var h4 = load3(s, 13) << 2
    var h5 = load4(s, 16)
    var h6 = load3(s, 20) << 7
    var h7 = load3(s, 23) << 5
    var h8 = load3(s, 26) << 4
    var h9 = (load3(s, 29) & 8388607) << 2

    val carry9 = (h9 + (1L << 24)) >> 25
    h0 += carry9 * 19
    h9 -= carry9 << 25
    val carry1 = (h1 + (1L << 24)) >> 25
    h2 += carry1
    h1 -= carry1 << 25
    val carry3 = (h3 + (1L << 24)) >> 25
    h4 += carry3
    h3 -= carry3 << 25
    val carry5 = (h5 + (1L << 24)) >> 25
    h6 += carry5
    h5 -= carry5 << 25
    val carry7 = (h7 + (1L << 24)) >> 25
    h8 += carry7
    h7 -= carry7 << 25

    val carry0 = (h0 + (1L << 25)) >> 26
    h1 += carry0
    h0 -= carry0 << 26
    val carry2 = (h2 + (1L << 25)) >> 26
    h3 += carry2
    h2 -= carry2 << 26
    val carry4 = (h4 + (1L << 25)) >> 26
    h5 += carry4
    h4 -= carry4 << 26
    val carry6 = (h6 + (1L << 25)) >> 26
    h7 += carry6
    h6 -= carry6 << 26
    val carry8 = (h8 + (1L << 25)) >> 26
    h9 += carry8
    h8 -= carry8 << 26

    h(0) = h0.toInt
    h(1) = h1.toInt
    h(2) = h2.toInt
    h(3) = h3.toInt
    h(4) = h4.toInt
    h(5) = h5.toInt
    h(6) = h6.toInt
    h(7) = h7.toInt
    h(8) = h8.toInt
    h(9) = h9.toInt
  }

  def toBytes(s: Array[Byte], h: Array[Int]) {
    var h0 = h(0)
    var h1 = h(1)
    var h2 = h(2)
    var h3 = h(3)
    var h4 = h(4)
    var h5 = h(5)
    var h6 = h(6)
    var h7 = h(7)
    var h8 = h(8)
    var h9 = h(9)

    var q = (19 * h9 + (1 << 24)) >> 25
    q = (h0 + q) >> 26
    q = (h1 + q) >> 25
    q = (h2 + q) >> 26
    q = (h3 + q) >> 25
    q = (h4 + q) >> 26
    q = (h5 + q) >> 25
    q = (h6 + q) >> 26
    q = (h7 + q) >> 25
    q = (h8 + q) >> 26
    q = (h9 + q) >> 25

    h0 += 19 * q

    val carry0 = h0 >> 26
    h1 += carry0
    h0 -= carry0 << 26
    val carry1 = h1 >> 25
    h2 += carry1
    h1 -= carry1 << 25
    val carry2 = h2 >> 26
    h3 += carry2
    h2 -= carry2 << 26
    val carry3 = h3 >> 25
    h4 += carry3
    h3 -= carry3 << 25
    val carry4 = h4 >> 26
    h5 += carry4
    h4 -= carry4 << 26
    val carry5 = h5 >> 25
    h6 += carry5
    h5 -= carry5 << 25
    val carry6 = h6 >> 26
    h7 += carry6
    h6 -= carry6 << 26
    val carry7 = h7 >> 25
    h8 += carry7
    h7 -= carry7 << 25
    val carry8 = h8 >> 26
    h9 += carry8
    h8 -= carry8 << 26
    val carry9 = h9 >> 25
    h9 -= carry9 << 25

    s(0) = h0.toByte
    s(1) = (h0 >>> 8).toByte
    s(2) = (h0 >>> 16).toByte
    s(3) = ((h0 >>> 24) | (h1 << 2)).toByte
    s(4) = (h1 >>> 6).toByte
    s(5) = (h1 >>> 14).toByte
    s(6) = ((h1 >>> 22) | (h2 << 3)).toByte
    s(7) = (h2 >>> 5).toByte
    s(8) = (h2 >>> 13).toByte
    s(9) = ((h2 >>> 21) | (h3 << 5)).toByte
    s(10) = (h3 >>> 3).toByte
    s(11) = (h3 >>> 11).toByte
    s(12) = ((h3 >>> 19) | (h4 << 6)).toByte
    s(13) = (h4 >>> 2).toByte
    s(14) = (h4 >>> 10).toByte
    s(15) = (h4 >>> 18).toByte
    s(16) = h5.toByte
    s(17) = (h5 >>> 8).toByte
    s(18) = (h5 >>> 16).toByte
    s(19) = ((h5 >>> 24) | (h6 << 1)).toByte
    s(20) = (h6 >>> 7).toByte
    s(21) = (h6 >>> 15).toByte
    s(22) = ((h6 >>> 23) | (h7 << 3)).toByte
    s(23) = (h7 >>> 5).toByte
    s(24) = (h7 >>> 13).toByte
    s(25) = ((h7 >>> 21) | (h8 << 4)).toByte
    s(26) = (h8 >>> 4).toByte
    s(27) = (h8 >>> 12).toByte
    s(28) = ((h8 >>> 20) | (h9 << 6)).toByte
    s(29) = (h9 >>> 2).toByte
    s(30) = (h9 >>> 10).toByte
    s(31) = (h9 >>> 18).toByte
  }

  def isNegative(f: Array[Int]): Int = {
    val s = new Array[Byte](32)
    toBytes(s, f)
    s(0) & 1
  }

  private val zero = new Array[Byte](32)

  def isNonZero(f: Array[Int]) = {
    val s = new Array[Byte](32)
    toBytes(s, f)
    Verify.cryptoVerify32(s, 0, zero)
  }

}
