import sbt._
import Keys._

object Build extends Build {

  lazy val root = Project(
    id = "nacl4s",
    base = file("."),
    settings = Seq(
      organization := "com.emstlk.nacl4s",
      version := "0.0.1-SNAPSHOT",
      scalaVersion := "2.11.6",
      scalacOptions ++= Seq("-encoding", "UTF-8", "-deprecation", "-unchecked", "-feature"),
      libraryDependencies ++= Seq(
        "org.scalatest" %% "scalatest" % "2.2.4" % "test" withSources()
      )
    )
  )

}
