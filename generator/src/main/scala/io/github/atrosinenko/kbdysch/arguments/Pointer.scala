package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.InvokerConstants._
import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

/**
 * A pointer to a **single** object of the referenced type.
 */
final case class Pointer(tpe: ArgDescriptionConstructor, direction: Direction) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription =
    ctx.setDirection(direction).createWith { thisCtx =>
      val pointee = tpe.instantiate(
        descriptions,
        thisCtx.spawnAux("pointee")
      )
      new PointerImpl(pointee, thisCtx)
    }
}
private class PointerImpl(pointee: ArgDescription, val ctx: GenContext) extends ArgDescription with ArgWithLength {
  override def lengthVarName: String = pointee.asInstanceOf[ArgWithLength].lengthVarName

  override def typeName: String = s"${pointee.typeName}_ptr"

  override def requiredTypes(): Seq[CType] = pointee.requiredTypes() :+ this

  override def requiredLocalVariables(): Seq[AuxRequest] = pointee.requiredLocalVariables() :+ new AuxRequest(pointee)

  override def globalDeclare(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"typedef ${pointee.typeName} *$typeName;")
  }

  override def globalDefine(formatter: SourceFormatter): Unit = {}

  override def initInstance(formatter: SourceFormatter): Unit = {
    pointee.initInstance(formatter)
    formatter.writeLn(s"$varName = &(${pointee.varName});")
  }

  override def deinitInstance(formatter: SourceFormatter): Unit = {
    pointee.deinitInstance(formatter)
  }

  override def processReturnValue(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"if (res_need_recurse_into_pointees($InvokerState, $Q$varName$Q, $refVarName, $varName)) {")
    formatter.indented {
      pointee.processReturnValue(formatter) // pointers cannot be returned from the kernel except for mmap, etc.?
    }
    formatter.writeLn(s"}")
  }
}