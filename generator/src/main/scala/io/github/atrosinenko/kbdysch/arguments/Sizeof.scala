package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class Sizeof(neighborName: String, tpe: ArgDescriptionConstructor = IntegerArg(64, false, IntegerRange.anyPositive)) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith { thisCtx =>
    new SizeofImpl(neighborName, tpe.instantiate(descriptions, thisCtx), thisCtx)
  }
}

private class SizeofImpl(neighborName: String, tpe: ArgDescription, val ctx: GenContext) extends ArgDescription with PrimitiveTypedArg with TriviallyDeclared {
  private val ref = ctx.findNeighbor(neighborName)

  override def typeName: String = tpe.typeName

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"$varName = ${ref.sizeof};")
  }

  override def processReturnValue(formatter: SourceFormatter): Unit = {
    // do nothing ?
  }
}