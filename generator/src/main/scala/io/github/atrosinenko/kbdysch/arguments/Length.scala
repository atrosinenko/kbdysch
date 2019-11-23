package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class Length(neighborName: String, tpe: ArgDescriptionConstructor) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith { thisCtx =>
    new LengthImpl(neighborName, tpe.instantiate(descriptions, thisCtx), thisCtx)
  }
}
private class LengthImpl(neighborName: String, tpe: ArgDescription, val ctx: GenContext) extends ArgDescription with PrimitiveTypedArg with TriviallyDeclared {
  private val ref = ctx.findNeighbor(neighborName)

  override def typeName: String = tpe.typeName

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"$varName = ${ref.asInstanceOf[ArgWithLength].lengthVarName};")
  }

  override protected def valueProcessor: String = "res_process_length"
}