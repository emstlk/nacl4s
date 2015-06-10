package com.emstlk.nacl4s

import java.nio.charset.Charset

import scala.language.implicitConversions

object NaCl {

  val charset = Charset.forName("UTF-8")

  implicit class StringConverter(s: String) {
    def asBytes = s.getBytes(charset)
  }

  implicit class BytesConverter(b: Array[Byte]) {
    def asString = new String(b, charset)
  }

  val Box = crypto.Box

  val SecretBox = crypto.SecretBox

  val KeyPair = crypto.KeyPair

  val SigningKeyPair = crypto.SigningKeyPair

  val SigningKey = crypto.SigningKey

  val VerifyKey = crypto.VerifyKey

}
