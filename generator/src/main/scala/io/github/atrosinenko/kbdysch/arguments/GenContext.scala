package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.Descriptions.Syscall
import io.github.atrosinenko.kbdysch.arguments.GenContext.Subscript

import scala.annotation.tailrec
import scala.collection.mutable.ArrayBuffer

object GenContext {
  def createSyscallWith(name: String, forComparison: Boolean)(op: GenContext => Syscall): Syscall = {
    val ctx = new GenContext(name)
    op(ctx)
  }
  sealed trait Spawn {
    def applyTo(oldCtx: GenContext): GenContext
  }
  private final case class SpawnArgument(argName: String) extends Spawn {
    override def applyTo(oldCtx: GenContext): GenContext = {
      val res = new GenContext(
        description = s"${oldCtx.description} / arg: $argName",
        realName = Some(argName),
        name = argName,
        baseStruct = None,
        subscripts = Nil,
        forComparison = oldCtx.forComparison,
        parentCtx = Some(oldCtx)
      )
      oldCtx.children += res
      res
    }
  }
  private final case class SpawnNested(memberName: String) extends Spawn {
    override def applyTo(oldCtx: GenContext): GenContext = {
      val res = new GenContext(
        description = s"${oldCtx.description} / nested: $memberName",
        realName = Some(memberName),
        name = memberName,
        baseStruct = Some(oldCtx),
        subscripts = Nil,
        forComparison = oldCtx.forComparison,
        parentCtx = Some(oldCtx)
      )
      oldCtx.children += res
      res
    }
  }
  private final case class SpawnIndexed(sub: Subscript) extends Spawn {
    override def applyTo(oldCtx: GenContext): GenContext = new GenContext(
      description= s"${oldCtx.description} / index level: ${oldCtx.indexDepth}",
      realName = None,
      name = s"${oldCtx.name}",
      baseStruct = None,
      subscripts = oldCtx.subscripts :+ sub,
      forComparison = oldCtx.forComparison,
      parentCtx = Some(oldCtx),
    )
  }
  private final case class SpawnAux(suffix: String) extends Spawn {
    override def applyTo(oldCtx: GenContext): GenContext = new GenContext(
      description = s"${oldCtx.description} / aux: $suffix",
      realName = None,
      name = s"${oldCtx.deepName}__$suffix",
      baseStruct = None,
      subscripts = oldCtx.deepSubscripts,
      forComparison = oldCtx.forComparison,
      parentCtx = Some(oldCtx.argRoot),
    )
  }

  final case class Subscript(size: String, index: String)
}

class GenContext private(
  val description: String,
  private val realName: Option[String],
  private val name: String,
  private val baseStruct: Option[GenContext],
  private val subscripts: Seq[Subscript],
  private val forComparison: Boolean,
  private val parentCtx: Option[GenContext],
) {
  import GenContext._

  def this(syscallName: String) = {
    this(syscallName, None, "", None, Nil, true, None)
  }

  private var _direction: Direction = Inherit
  private var _ownArg: ArgDescription = _
  private val children = ArrayBuffer[GenContext]()

  def createWith(op: this.type => ArgDescription): ArgDescription = {
    _ownArg = op(this)
    _ownArg
  }

  def spawnArgument(name: String): GenContext = SpawnArgument(name).applyTo(this)

  def spawnNested(name: String): GenContext = SpawnNested(name).applyTo(this)

  def spawnIndexed(max: Int, index: String): GenContext = SpawnIndexed(Subscript(size = max.toString, index)).applyTo(this)

  def spawnAux(suffix: String): GenContext = SpawnAux(suffix).applyTo(this)

  def deepName: String = {
    baseStruct match {
      case Some(value) => s"${value.deepName}_$name"
      case None => name
    }
  }

  def deepSubscripts: Seq[Subscript] = {
    baseStruct match {
      case Some(value) => value.deepSubscripts ++ subscripts
      case None => subscripts
    }
  }

  def argRoot: GenContext = if (parentCtx.get.parentCtx.isEmpty)
    this
  else
    parentCtx.get.argRoot

  def setDirection(dir: Direction): GenContext = {
    _direction = dir
    this
  }

  @tailrec
  final def direction: Direction = if (_direction == Inherit) {
    parentCtx.get.direction
  } else {
    _direction
  }

  def indexDepth: Int = subscripts.length
  def indexesWith: String = s"ind_$indexDepth"

  def deepBaseStruct: Option[GenContext] = baseStruct.orElse(parentCtx.flatMap(_.deepBaseStruct))

  def fullDeclaredName: String = {
    val subscriptStr = subscripts.map(s => s"[${s.size}]").mkString
    val partCount = if (forComparison) "[MAX_PART_COUNT]" else ""
    deepBaseStruct match {
      case Some(structRef) => s"${structRef.fullDeclaredName}.$name$subscriptStr"
      case None => s"$name$partCount$subscriptStr"
    }
  }

  def fullVarName(isPart0: Boolean): String = {
    val subscriptStr = subscripts.map(s => s"[${s.index}]").mkString
    val partIndex = if (forComparison) {
      if (isPart0) "[0]" else "[part]"
    } else {
      ""
    }
    deepBaseStruct match {
      case Some(structRef) => s"${structRef.fullVarName(isPart0)}.$name$subscriptStr"
      case None => s"$name$partIndex$subscriptStr"
    }
  }

  def findNeighbor(name: String): ArgDescription = {
    val resultOption = parentCtx.get.children.find { neighbor =>
      neighbor.realName.contains(name)
    }
    if (resultOption.isEmpty) {
      println(s"Error: Cannot find $name in ${parentCtx.get._ownArg.varName} at $description")
      println(s"Error: Existing names: ${parentCtx.get.children.filter(_.realName.nonEmpty).map(child => child.realName.get).mkString(", ")}.")
      System.exit(1)
    }
    resultOption.get._ownArg
  }

  override def toString: String = s"GenContext($description)"
}
