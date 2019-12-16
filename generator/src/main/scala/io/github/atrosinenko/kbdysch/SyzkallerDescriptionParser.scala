package io.github.atrosinenko.kbdysch

import java.io.File
import java.nio.file.Files

import fastparse.all._
import fastparse.core.Parsed.{Failure, Success}
import io.github.atrosinenko.kbdysch.arguments.{ArgDescriptionConstructor, ArrayArg, Buffer, Const, DelFD, Direction, Errno, Fd, FileName, Flags, In, InOut, Inherit, IntegerArg, IntegerRange, Length, Out, Pointer, Ref, Sizeof, StringRes}

import scala.collection.JavaConverters._

object SyzkallerDescriptionParser {
  import Descriptions._

  private object Parts {
    val NlCh = ';'
    val NL = s"$NlCh"

    val letter: Parser[Unit] = P(CharIn('a' to 'z') | CharIn('A' to 'Z'))
    val digit: Parser[Unit] = P(CharIn('0' to '9'))
    val singleWhitespace: Parser[Unit] = P(CharIn(" \t"))
    val ws: Parser[Unit] = singleWhitespace.rep(1)
    val optws: Parser[Unit] = singleWhitespace.rep()

    def parseDirection(str: String): Direction = str match {
      case "in" => In
      case "out" => Out
      case "inout" => InOut
    }

    val ident: Parser[String] = P(((letter | CharIn("_")) ~ (letter | digit | CharIn("_")).rep).!)
    val someString: Parser[String] = P((letter | digit | CharIn("_\\.")).rep(1).!)

    val integer: Parser[Int] = P(("-".? ~ digit.rep(1)).!.map(_.toInt))
    val range: Parser[IntegerRange] = P(integer ~ ":" ~ integer).map {
      case (min, max) => IntegerRange(min, max)
    }

    val typeName: Parser[String] = P((
      "const" | "int8" | "int16" | "int32" | "int64" | "intptr" |
        "flags" | "array" | "ptr" | "ptr64" |
        "fd_dir" | "fd" | "delfd" | "buffer" |
        "fileoff" | "len" | "bytesize" | "sizeof" | "pid" |
        "uid" | "gid" | "signalno"
      ).!)

    val tpe: Parser[ArgDescriptionConstructor] = P(typeName ~ ("[" ~ (range | integer | tpe | someString).rep(1, optws ~ "," ~ optws) ~ "]").?)
      .map {
        case (n, opts) => (n, opts.getOrElse(Nil).filterNot(_ == "opt" /* TODO */))
      }
      .map {
        // TODO kludge
        case ("ptr" | "ptr64", Seq("in", "filename")) => Pointer(FileName(), In)
        case ("ptr" | "ptr64", Seq(dir: String, "string")) => Pointer(StringRes(), parseDirection(dir))
        case ("ptr", Seq(dir: String, Length(varName, _tpe))) =>
          Pointer(Sizeof(varName, _tpe), parseDirection(dir))
        case ("ptr", Seq(dir: String, _tpe: ArgDescriptionConstructor)) =>
          Pointer(_tpe, parseDirection(dir))

        case ("const", Seq(value)) => Const(value.toString, IntegerArg(32, false))
        case ("const", Seq(value, t)) => Const(value.toString, parseTypeOrRef(t))

        case ("sock_port", Seq()) => IntegerArg(16, false)
        case ("int8", Seq()) => IntegerArg(8, true)
        case ("int8", Seq(range: IntegerRange)) => IntegerArg(8, true, range)
        case ("int16", Seq()) => IntegerArg(16, true)
        case ("int16", Seq(range: IntegerRange)) => IntegerArg(16, true, range)
        case ("int32", Seq()) => IntegerArg(32, true)
        case ("int32", Seq(range: IntegerRange)) => IntegerArg(32, true, range)
        case ("int64", Seq()) => IntegerArg(64, true)
        case ("intptr", Seq()) => IntegerArg(64, false)
        case ("int64" , Seq(range: IntegerRange)) => IntegerArg(64, true, range)
        case ("intptr", Seq(range: IntegerRange)) => IntegerArg(64, false, range)

        case ("flags", Seq(enumId: String)) => Flags(enumId, IntegerArg(32, false))
        case ("flags", Seq(enumId: String, t: ArgDescriptionConstructor)) => Flags(enumId, t)

        case ("array", Seq(t)) => ArrayArg(parseTypeOrRef(t))
        case ("array", Seq(t, len: Int)) => ArrayArg(parseTypeOrRef(t), IntegerRange(len, len))
        case ("array", Seq(t, r: IntegerRange)) => ArrayArg(parseTypeOrRef(t), r)

        case ("ptr" | "ptr64", Seq(dir: String, t)) => Pointer(parseTypeOrRef(t), parseDirection(dir))
        case ("fd" | "sock" | "fd_dir", Seq()) => Fd()
        case ("delfd", Seq()) => DelFD()
        case ("buffer", Seq()) => Buffer(Inherit)
        case ("buffer", Seq(dir: String)) => Buffer(parseDirection(dir))
        case ("fileoff", Seq()) => IntegerArg(32, true)
        case ("fileoff", Seq(t: ArgDescriptionConstructor)) => t
        case ("len", Seq(name: String)) => Length(name, IntegerArg(64, false))
        case ("len", Seq(name: String, _tpe: ArgDescriptionConstructor)) => Length(name, _tpe)
        case ("sizeof", Seq(name: String)) => Sizeof(name, IntegerArg(64, false))
        case ("sizeof", Seq(name: String, tpe: ArgDescriptionConstructor)) => Sizeof(name, tpe)

        case ("uid" | "gid" | "pid" | "signalno", Seq()) => IntegerArg(32, true)
      }

    def parseTypeOrRef(obj: Any): ArgDescriptionConstructor = obj match {
      case t: ArgDescriptionConstructor => t
      case name: String => Ref(name)
    }

    val assertion: Parser[Assertion] = P(
      ("@" ~ ident).map(ident => Assertion(Seq(lvalue => s"$ident($lvalue)"))) |
        ("@{" ~ CharsWhile(_ != '}').! ~ "}").map(expr => Assertion(Seq(lvalue => s"assert(${expr.replace("_", lvalue)})")))
    )

    val assertions: Parser[Seq[Assertion]] = P(optws ~ assertion.rep(0, ws) ~ optws)

    val syscall: Parser[SyscallConstructor] = P(ident ~ ("$" ~ ident).? ~ "(" ~ (ident ~ ws ~ tpe ~ assertions).rep(0, optws ~ "," ~ optws) ~ ")" ~ optws ~ tpe.? ~ assertions ~ NL).map {
      case (name, token, args, ret, retAssertions) =>
        SyscallConstructor(name, args.map(x => AnnotatedArgConstructor(x._1, x._2, x._3)), AnnotatedArgConstructor("res", ret.getOrElse(Errno()), retAssertions))
    }

    def structLike(start: String, end: String, isUnion: Boolean): Parser[StructLike] = P(ident ~ optws ~ start ~ optws ~ NL ~ (optws ~ ident ~ ws ~ (tpe | someString) ~ assertions ~ NL).rep(1) ~ optws ~ end ~ optws ~ NL).map {
      case (name, fields) => StructLike(name, fields.map {
        case (subname, _tpe: ArgDescriptionConstructor, assertions) => AnnotatedArgConstructor(subname, _tpe, assertions)
        case (subname, typeName: String, assertions) => AnnotatedArgConstructor(subname, Ref(typeName), assertions)
      }, isUnion)
    }

    val struct: Parser[StructLike] = structLike("{", "}", isUnion = false)
    val union: Parser[StructLike] = structLike("[", "]", isUnion = true)

    val enum: Parser[EnumItem] = P(ident ~ optws ~ "=" ~ optws ~ (("\"" ~ someString ~ "\"") | someString).!.rep(1, optws ~ "," ~ optws) ~ NL).map {
      case (name, options) => EnumItem(name, options)
    }

    val include: Parser[Include] = P(optws ~ "include" ~ optws ~ "<" ~ CharsWhile(_ != '>').! ~ ">" ~ optws ~ NL).map(Include)

    val define: Parser[Define] = P(optws ~ "define" ~ CharsWhile(_ != NlCh).! ~ NL).map(Define)

    val item: Parser[DescriptionItem] = P(syscall | struct | union | enum | include | define)

    val wholeFile: Parser[Seq[DescriptionItem]] = P(item.rep ~ End)
  }

  def parse(fileContents: Seq[String]): Either[String, Descriptions] = {
    val data = fileContents.map(_ + Parts.NL).mkString("")
    Parts.wholeFile.parse(data) match {
      case Success(value, _) =>
        Right(new Descriptions(value))
      case Failure(lastParser, index, extra) =>
        Left(s"Cannot parse: ${extra.toString}")
    }
  }

  def parse(file: File): Either[String, Descriptions] = {
    parse(Files.readAllLines(file.toPath).asScala.map(_.trim).filterNot( str =>
      str.isEmpty || str.startsWith("#")
    ))
  }
}
