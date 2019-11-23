package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.InvokerConstants._
import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}
import io.github.atrosinenko.kbdysch.Descriptions.EnumItem

final case class Flags(enumId: String, tpe: ArgDescriptionConstructor = IntegerArg(32, signed = false)) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith { thisCtx =>
    new FlagsImpl(
      descriptions.enums(enumId),
      tpe.instantiate(descriptions, thisCtx),
      thisCtx)
  }
}

private class FlagsImpl(enum: EnumItem, tpe: ArgDescription, val ctx: GenContext) extends ArgDescription with PrimitiveTypedArg {
  override def typeName: String = tpe.typeName

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"$varName = ${enum.valueGeneratorName}($InvokerState, $Q$varName$Q);")
  }

  override def deinitInstance(formatter: SourceFormatter): Unit =
    tpe.deinitInstance(formatter)

  override def processReturnValue(formatter: SourceFormatter): Unit =
    tpe.processReturnValue(formatter)
}