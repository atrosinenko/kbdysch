package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class Errno() extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith(new ErrnoImpl(_))
}

private class ErrnoImpl(val ctx: GenContext) extends ArgDescription with PrimitiveTypedArg with TriviallyDeclared {
  override def typeName: String = "int64_t"

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"$varName = 0;")
  }

  override protected def valueProcessor: String = "res_process_errno"
}