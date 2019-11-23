package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class Const(value: String, tpe: ArgDescriptionConstructor) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith { thisCtx =>
    new ConstImpl(value, tpe.instantiate(descriptions, thisCtx), thisCtx)
  }
}

private class ConstImpl(value: String, tpe: ArgDescription, val ctx: GenContext) extends ArgDescription {
  override def typeName: String = tpe.typeName

  override def globalDeclare(formatter: SourceFormatter): Unit = tpe.globalDeclare(formatter)
  override def globalDefine(formatter: SourceFormatter): Unit = tpe.globalDefine(formatter)

  override def requiredTypes(): Seq[CType] =
    tpe.requiredTypes()
  override def requiredLocalVariables(): Seq[AuxRequest] =
    tpe.requiredLocalVariables()

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"$varName = $value;")
  }

  override def deinitInstance(formatter: SourceFormatter): Unit =
    tpe.deinitInstance(formatter)

  override def processReturnValue(formatter: SourceFormatter): Unit = {}
}
