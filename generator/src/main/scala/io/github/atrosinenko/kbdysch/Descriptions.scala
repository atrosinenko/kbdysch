package io.github.atrosinenko.kbdysch

import io.github.atrosinenko.kbdysch.Descriptions._
import io.github.atrosinenko.kbdysch.arguments.{ArgDescription, ArgDescriptionConstructor, GenContext}

import scala.util.control.NonFatal

object Descriptions {
  final case class Assertion(stmts: Seq[String => String])
  final case class AnnotatedArgConstructor(name: String, tpe: ArgDescriptionConstructor, assertions: Seq[Assertion]) {
    def instantiate(descriptions: Descriptions, ctx: GenContext): AnnotatedArg = AnnotatedArg(
      name,
      ctx.createWith(thisCtx =>tpe.instantiate(descriptions, thisCtx)),
      assertions
    )
  }
  final case class AnnotatedArg(name: String, tpe: ArgDescription, assertions: Seq[Assertion])

  sealed trait DescriptionItem

  final case class SyscallConstructor(name: String, args: Seq[AnnotatedArgConstructor], ret: AnnotatedArgConstructor) extends DescriptionItem {
    def instantiate(descriptions: Descriptions, ctx: GenContext) = Syscall(
      name,
      args.map { arg => arg.instantiate(descriptions, ctx.spawnArgument(arg.name)) },
      ret.instantiate(descriptions, ctx.spawnArgument("_res_"))
    )
  }

  final case class Syscall(name: String, args: Seq[AnnotatedArg], ret: AnnotatedArg) {
    def allVariables: Seq[AnnotatedArg] = args :+ ret
  }
  final case class IndexedSyscall(syscall: Syscall, globalIndex: Int, localIndex: Int) {
    def invokerName: String = s"invoke_${syscall.name}_$localIndex"
  }

  final case class StructLike(name: String, fields: Seq[AnnotatedArgConstructor], isUnion: Boolean) extends DescriptionItem

  final case class EnumItem(name: String, options: Seq[String]) extends DescriptionItem {
    def hasStringType: Boolean = options.exists { opt =>
      opt.contains('"')
    }
    def valueGeneratorName: String = s"gen_enum_$name"
  }

  sealed trait RawItem extends DescriptionItem {
    def line: String
  }
  final case class Include(file: String) extends RawItem {
    override def line: String = s"#include <$file>"
  }
  final case class Define(str: String) extends RawItem {
    override def line: String = s"#define $str"
  }
}

class Descriptions(items: Seq[DescriptionItem]) {
  val structs:  Map[String, StructLike] = items.collect { case x: StructLike => (x.name, x) }.toMap
  val enums:    Map[String, EnumItem]   = items.collect { case x: EnumItem => (x.name, x) }.toMap
  val comments: Seq[RawItem]            = items.collect { case x: RawItem => x }
  // the above items should be initialized before constructing syscalls
  val syscalls: Seq[Syscall]            = items.collect {
    case x: SyscallConstructor =>
      try {
        GenContext.createSyscallWith(x.name, true) { ctx =>
          x.instantiate(this, ctx)
        }
      } catch {
        case NonFatal(ex) =>
          println(s"Error during processing syscall: ${x.name}")
          ex.printStackTrace()
          System.exit(1)
          ??? // not reached
      }
  }

  private val globallyIndexedSyscalls: Iterable[Seq[(Syscall, Int)]] = syscalls
    .zipWithIndex
    .groupBy { case (syscall, _) => syscall.name }
    .values

  val indexedSyscalls: Seq[IndexedSyscall] = globallyIndexedSyscalls
    .flatMap { group: Seq[(Syscall, Int)] => group.zipWithIndex }
    .map {
      case ((syscall, globalIndex), localIndex) => IndexedSyscall(syscall, globalIndex, localIndex)
    }
    .toSeq
    .sortBy(_.globalIndex)
}
