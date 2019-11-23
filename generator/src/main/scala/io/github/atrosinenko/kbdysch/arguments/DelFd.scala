package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class DelFD() extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith(new DefFDImpl(_))
}

private class DefFDImpl(val ctx: GenContext) extends ArgDescription with PrimitiveTypedArg with TriviallyDeclared {
  override def typeName: String = "int64_t"

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"$varName = -1;")
  }

  override protected def valueProcessor: String = "res_unregister_fd"
}