package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.InvokerConstants._
import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class Fd() extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith(new FdImpl(_))
}

private class FdImpl(val ctx: GenContext) extends ArgDescription with PrimitiveTypedArg with TriviallyDeclared {
  override def typeName: String = "int"

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"$varName = res_get_fd($InvokerState, $Q$varName$Q);")
  }

  override protected def valueProcessor: String = "res_process_fd"
}