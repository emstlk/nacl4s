package com.emstlk.nacl4s

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.box.Curve25519XSalsa20Poly1305
import com.emstlk.nacl4s.crypto.core._
import com.emstlk.nacl4s.crypto.hash.Sha512
import com.emstlk.nacl4s.crypto.onetimeauth.Poly1305
import com.emstlk.nacl4s.crypto.scalarmult.Curve25519
import com.emstlk.nacl4s.crypto.secretbox.XSalsa20Poly1305
import com.emstlk.nacl4s.crypto.sign.Ed25519
import com.emstlk.nacl4s.crypto.stream.XSalsa20
import com.emstlk.nacl4s.crypto.verify.Verify
import org.scalatest._
import org.scalatest.prop._

import scala.io.Source

class NaClSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  def toHex(a: Array[Byte]) = a.map("%02x" format _).mkString

  def fromHex(s: String) = s.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)

  describe("Salsa20") {

    import Salsa20._

    it("first case") {
      val key = fromHex("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4")
      val c = fromHex("657870616e642033322d62797465206b")
      val out = new Array[Byte](outputBytes)
      val expectedOut = "a763249cfc79b52add4d52000bae41c0b7fa0e72368ae15495a1a50714d5c020" +
        "8c2f5ba72de4cf3ddce7efd71d2aebf22d19b607e6647446f4284fa4b89d5d91"
      cryptoCore(out, new Array[Byte](constBytes), key, c)
      toHex(out) shouldBe expectedOut
    }

    it("second case") {
      val k = fromHex("0102030405060708090a0b0c0d0e0f10c9cacbcccdcecfd0d1d2d3d4d5d6d7d8")
      val in = fromHex("65666768696a6b6c6d6e6f7071727374")
      val c = fromHex("657870616e642033322d62797465206b")
      val out = new Array[Byte](outputBytes)
      val expectedOut = "45254427290f6bc1ff8b7a06aae9d9625990b66a1533c841ef31de22d772287e" +
        "68c507e1c5991f02664e4cb054f5f6b8b1a0858206489577c0c384ecea67f64a"
      cryptoCore(out, in, k, c)
      toHex(out) shouldBe expectedOut
    }

    it("third case") {
      val k = fromHex("ee304fca27008d8c126f90027901d80f7f1d8b8dc936cf3b9f819692827e5777")
      val in = fromHex("81918ef2a5e0da9b3e9060521e4bb352")
      val c = fromHex("657870616e642033322d62797465206b")
      val out = new Array[Byte](outputBytes)
      cryptoCore(out, in, k, c)

      def show(x: Array[Byte], xoffset: Int, y: Array[Byte], yoffset: Int) = {
        var borrow = 0
        (0 until 4).map { i =>
          val xi = x(xoffset + i) & 0xff
          val yi = y(yoffset + i) & 0xff
          val res = "%02x".format((xi - yi - borrow) & 0xff)
          borrow = if (xi < yi + borrow) 1 else 0
          res
        }.mkString
      }

      show(out, 0, c, 0) shouldBe "bc1b30fc"
      show(out, 20, c, 4) shouldBe "072cc140"
      show(out, 40, c, 8) shouldBe "75e4baa7"
      show(out, 60, c, 12) shouldBe "31b5a845"
      show(out, 24, in, 0) shouldBe "ea9b11e9"
      show(out, 28, in, 4) shouldBe "a5191f94"
      show(out, 32, in, 8) shouldBe "e18cba8f"
      show(out, 36, in, 12) shouldBe "d821a7cd"
    }

    it("fourth case") {
      val key = fromHex("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4")
      val nonce = fromHex("8219e0036b7a0b37")
      val out = new Array[Byte](outputBytes)
      val expectedOut = "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880" +
        "309e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c093c5e55855796"
      cryptoStream(out, out.length, nonce, 0, key)
      toHex(out) shouldBe expectedOut
    }

  }

  describe("HSalsa20") {

    import HSalsa20._

    it("first case") {
      val shared = fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
      val c = fromHex("657870616e642033322d62797465206b")
      val key = new Array[Byte](keyBytes)
      cryptoCore(key, new Array[Byte](inputBytes), shared, c)
      toHex(key) shouldBe "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
    }

    it("second case") {
      val firstKey = fromHex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
      val nonce = fromHex("69696ee955b62b73cd62bda875fc73d6")
      val c = fromHex("657870616e642033322d62797465206b")
      val secondKey = new Array[Byte](keyBytes)
      cryptoCore(secondKey, nonce, firstKey, c)
      toHex(secondKey) shouldBe "dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4"
    }

    it("third case") {
      val k = fromHex("ee304fca27008d8c126f90027901d80f7f1d8b8dc936cf3b9f819692827e5777")
      val in = fromHex("81918ef2a5e0da9b3e9060521e4bb352")
      val c = fromHex("657870616e642033322d62797465206b")
      val out = new Array[Byte](outputBytes)
      cryptoCore(out, in, k, c)
      toHex(out) shouldBe "bc1b30fc072cc14075e4baa731b5a845ea9b11e9a5191f94e18cba8fd821a7cd"
    }

  }

  describe("XSalsa20") {

    import XSalsa20._

    it("first case") {
      val key = fromHex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
      val nonce = fromHex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
      val out = new Array[Byte](64)
      val expectedOut = "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880" +
        "309e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c093c5e55855796"
      cryptoStream(out, out.length, nonce, key)
      toHex(out) shouldBe expectedOut
    }

    it("second case") {
      val key = fromHex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
      val nonce = fromHex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
      val rs = new Array[Byte](32)
      cryptoStream(rs, rs.length, nonce, key)
      toHex(rs) shouldBe "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
    }

    it("third case") {
      val key = fromHex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
      val nonce = fromHex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
      val m = fromHex("0000000000000000000000000000000000000000000000000000000000000000" +
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
        "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
        "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
        "5e0705")
      val expectedC = "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
        "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
        "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da" +
        "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
        "e355a5"
      val c = new Array[Byte](163)
      cryptoStreamXor(c, m, m.length, nonce, key)
      toHex(c.drop(32)) shouldBe expectedC
    }

  }

  describe("Poly1305") {

    import Poly1305._

    it("first case") {
      val rs = fromHex("eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880")

      val c = fromHex("8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
        "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
        "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da" +
        "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
        "e355a5")

      val mac = new Array[Byte](16)
      cryptoOneTimeAuth(mac, 0, c, 0, c.length, rs)
      toHex(mac) shouldBe "f3ffc7703f9400e52a7dfb4b3d3305d9"

      noException should be thrownBy {
        cryptoOneTimeAuthVerify(mac, 0, c, 0, c.length, rs)
      }
    }

    it("random 10000 cases") {
      val key = new Array[Byte](32)
      val c = new Array[Byte](10000)
      val a = new Array[Byte](16)

      var length = 0
      while (length < 10000) {
        random.nextBytes(key)
        random.nextBytes(c)

        cryptoOneTimeAuth(a, 0, c, 0, length, key)
        noException should be thrownBy {
          cryptoOneTimeAuthVerify(a, 0, c, 0, length, key)
        }

        if (length > 0) {
          var idx = random.nextInt(length)
          c(idx) = (c(idx) + random.nextInt(255) + 1).toByte
          the[RuntimeException] thrownBy {
            cryptoOneTimeAuthVerify(a, 0, c, 0, length, key)
          }

          idx = random.nextInt(a.length)
          a(idx) = (a(idx) + random.nextInt(255) + 1).toByte
          the[RuntimeException] thrownBy {
            cryptoOneTimeAuthVerify(a, 0, c, 0, length, key)
          }
        }
        length += 1
      }
    }

  }

  describe("Curve25519") {

    import Curve25519._

    it("first case") {
      val alicesk = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
      val alicepk = new Array[Byte](bytes)
      cryptoScalarmultBase(alicepk, alicesk)
      toHex(alicepk) shouldBe "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    }

    it("second case") {
      val bobsk = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
      val bobpk = new Array[Byte](bytes)
      cryptoScalarmultBase(bobpk, bobsk)
      toHex(bobpk) shouldBe "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    }

    it("third case") {
      val alicesk = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
      val bobpk = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
      val k = new Array[Byte](bytes)
      cryptoScalarmult(k, alicesk, bobpk)
      toHex(k) shouldBe "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    }

    it("fourth case") {
      val bobsk = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
      val alicepk = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
      val k = new Array[Byte](bytes)
      cryptoScalarmult(k, bobsk, alicepk)
      toHex(k) shouldBe "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    }

    it("fifth case") {
      val p1 = fromHex("7220f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4eea")
      val p2 = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
      val out1 = new Array[Byte](bytes)
      val out2 = new Array[Byte](bytes)
      val scalar = new Array[Byte](scalarBytes)
      scalar(0) = 1

      cryptoScalarmult(out1, scalar, p1)
      cryptoScalarmult(out2, scalar, p2)
      toHex(out1) shouldBe "03ad4080c2910b5e0be22f6c5f7c7e08e642462ef0ec93a654c5c34dc95b556d"
      toHex(out2) shouldBe "2108adf6afe8883b77ac565e807159be646f7f35275bb0a9bc4ed29759ee665b"
    }

  }

  describe("Verify") {

    import Verify._

    it("first case") {
      val v16 = new Array[Byte](16)
      val v32 = new Array[Byte](32)
      random.nextBytes(v16)
      random.nextBytes(v32)

      val v16x = new Array[Byte](16)
      val v32x = new Array[Byte](32)
      Array.copy(v16, 0, v16x, 0, 16)
      Array.copy(v32, 0, v32x, 0, 32)

      cryptoVerify16(v16, 0, v16x) shouldBe true
      cryptoVerify32(v32, 0, v32x) shouldBe true

      var idx = random.nextInt(v16x.length)
      v16x(idx) = (v16x(idx) + 1).toByte
      idx = random.nextInt(v32x.length)
      v32x(idx) = (v32x(idx) + 1).toByte

      cryptoVerify16(v16, 0, v16x) shouldBe false
      cryptoVerify32(v32, 0, v32x) shouldBe false
    }

  }

  describe("XSalsa20Poly1305") {

    import XSalsa20Poly1305._

    it("first case") {
      val key = fromHex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
      val nonce = fromHex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
      val m = fromHex("0000000000000000000000000000000000000000000000000000000000000000" +
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
        "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
        "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
        "5e0705")
      val expectedC = "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce" +
        "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972" +
        "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae" +
        "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3" +
        "7973f622a43d14a6599b1f654cb45a74e355a5"
      val c = new Array[Byte](163)
      cryptoSecretBox(c, m, m.length, nonce, key)
      toHex(c.drop(boxZeroBytes)) shouldBe expectedC
    }

    it("second case") {
      val key = fromHex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
      val nonce = fromHex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
      val c = fromHex("00000000000000000000000000000000f3ffc7703f9400e52a7dfb4b3d3305d9" +
        "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
        "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
        "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da" +
        "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
        "e355a5")
      val expectedM = "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
        "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
        "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
        "5e0705"
      val m = new Array[Byte](163)
      cryptoSecretBoxOpen(m, c, c.length, nonce, key)
      toHex(m.drop(zeroBytes)) shouldBe expectedM
    }

    it("random 1000 cases") {
      val k = new Array[Byte](keyBytes)
      val n = new Array[Byte](nonceBytes)
      val m = new Array[Byte](10000)
      val c = new Array[Byte](10000)
      val m2 = new Array[Byte](10000)

      var length = 0
      while (length < 1000) {
        random.nextBytes(k)
        random.nextBytes(n)
        random.nextBytes(m)
        var i = 0
        while (i < zeroBytes) {
          m(i) = 0
          i += 1
        }
        cryptoSecretBox(c, m, length + zeroBytes, n, k)

        cryptoSecretBoxOpen(m2, c, length + zeroBytes, n, k)
        m2.take(length + zeroBytes) shouldBe m.take(length + zeroBytes)

        val idx = boxZeroBytes + random.nextInt(length + boxZeroBytes)
        c(idx) = (c(idx) + random.nextInt(255) + 1).toByte
        the[RuntimeException] thrownBy {
          cryptoSecretBoxOpen(m2, c, length + zeroBytes, n, k)
        }
        length += 1
      }
    }

  }

  describe("Curve25519XSalsa20Poly1305") {

    import Curve25519XSalsa20Poly1305._

    it("first case") {
      val sk = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
      val pk = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
      val nonce = fromHex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
      val m = fromHex("0000000000000000000000000000000000000000000000000000000000000000" +
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
        "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
        "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
        "5e0705")
      val expectedC = "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce" +
        "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972" +
        "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae" +
        "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3" +
        "7973f622a43d14a6599b1f654cb45a74e355a5"

      val c = new Array[Byte](163)
      cryptoBox(c, m, m.length, nonce, pk, sk)
      toHex(c.drop(boxZeroBytes)) shouldBe expectedC
    }

    it("second case") {
      val sk = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
      val pk = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
      val nonce = fromHex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
      val c = fromHex("00000000000000000000000000000000f3ffc7703f9400e52a7dfb4b3d3305d9" +
        "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
        "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
        "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da" +
        "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
        "e355a5")
      val expectedM = "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
        "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
        "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
        "5e0705"
      val m = new Array[Byte](163)

      cryptoBoxOpen(m, c, c.length, nonce, pk, sk)
      toHex(m.drop(zeroBytes)) shouldBe expectedM
    }

    it("random 1000 cases") {
      val alicesk = new Array[Byte](secretKeyBytes)
      val alicepk = new Array[Byte](publicKeyBytes)
      val bobsk = new Array[Byte](secretKeyBytes)
      val bobpk = new Array[Byte](publicKeyBytes)
      val n = new Array[Byte](nonceBytes)
      val m = new Array[Byte](10000)
      val c = new Array[Byte](10000)
      val m2 = new Array[Byte](10000)

      var length = 0
      while (length < 1000) {
        cryptoBoxKeypair(alicepk, alicesk)
        cryptoBoxKeypair(bobpk, bobsk)
        random.nextBytes(n)
        random.nextBytes(m)
        var i = 0
        while (i < zeroBytes) {
          m(i) = 0
          i += 1
        }
        cryptoBox(c, m, length + zeroBytes, n, bobpk, alicesk)

        cryptoBoxOpen(m2, c, length + zeroBytes, n, alicepk, bobsk)
        m2.take(length + zeroBytes) shouldBe m.take(length + zeroBytes)

        val idx = boxZeroBytes + random.nextInt(length + boxZeroBytes)
        c(idx) = (c(idx) + random.nextInt(255) + 1).toByte
        the[RuntimeException] thrownBy {
          cryptoBoxOpen(m2, c, length + zeroBytes, n, alicepk, bobsk)
        }
        length += 1
      }
    }

  }

  describe("Sha512") {

    import Sha512._

    it("first case") {
      val x = "testing\n".getBytes
      val x2 = ("The Conscience of a Hacker is a small essay written January 8, 1986 by a computer security hacker " +
        "who went by the handle of The Mentor, who belonged to the 2nd generation of Legion of Doom.").getBytes
      val hash = new Array[Byte](bytes)
      val expectedHashX = "24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5" +
        "931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28"
      val expectedHashX2 = "a77abe1ccf8f5497e228fbc0acd73a521ededb21b89726684a6ebbc3baa32361" +
        "aca5a244daa84f24bf19c68baf78e6907625a659b15479eb7bd426fc62aafa73"
      cryptoHash(hash, x, x.length.toLong)
      toHex(hash) shouldBe expectedHashX

      cryptoHash(hash, x2, x2.length.toLong)
      toHex(hash) shouldBe expectedHashX2
    }

  }

  describe("Ed25519") {

    import Ed25519._

    it("1024 cases of various length") {
      val out = new Array[Byte](1024 + bytes)

      for (line <- Source.fromFile("src/test/data/sign_data").getLines()) {
        val data = line.split(',')
        val sk = fromHex(data(0))
        val pk = fromHex(data(1))
        val signature = data(2)
        val msg = if (data.length == 3) Array.empty[Byte] else fromHex(data(3))

        cryptoSign(out, msg, msg.length, sk ++ pk)
        toHex(out.take(bytes)) shouldBe signature
        noException shouldBe thrownBy {
          cryptoSignOpen(msg, out, bytes + msg.length, pk)
        }
      }
    }

    it("generate signing key pair") {
      val pk = new Array[Byte](publicKeyBytes)
      val sk = new Array[Byte](secretKeyBytes)
      val seed = "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee"
      cryptoSignSeedKeyPair(pk, sk, fromHex(seed))
      toHex(pk) shouldBe "b5076a8474a832daee4dd5b4040983b6623b5f344aca57d4d6ee4baf3f259e6e"
      toHex(sk) shouldBe (seed + "b5076a8474a832daee4dd5b4040983b6623b5f344aca57d4d6ee4baf3f259e6e")
    }

  }

  describe("Api") {

    it("check box") {
      forAll { message: String =>
        val aliceKeys = KeyPair()
        val bobKeys = KeyPair()

        val aliceBox = Box(bobKeys.publicKey, aliceKeys.privateKey)
        val nonce = Box.randomNonce()
        val encrypted = aliceBox.encrypt(nonce, message.asBytes)

        val bobBox = Box(aliceKeys.publicKey, bobKeys.privateKey)
        bobBox.decrypt(nonce, encrypted).asString shouldBe message
      }
    }

    it("check secret box") {
      forAll { message: String =>
        val myBox = SecretBox.withRandomKey()
        val key = myBox.key

        val nonce = SecretBox.randomNonce()
        val encrypted = myBox.encrypt(nonce, message.asBytes)

        val friendBox = SecretBox(key)
        friendBox.decrypt(nonce, encrypted).asString shouldBe message
      }
    }

    it("check signing key pair") {
      forAll { message: String =>
        val keys = SigningKeyPair()
        val msg = message.asBytes
        val signature = SigningKey(keys.privateKey).sign(msg)
        noException shouldBe thrownBy {
          VerifyKey(keys.publicKey).verify(msg, signature)
        }
      }
    }

  }

}
