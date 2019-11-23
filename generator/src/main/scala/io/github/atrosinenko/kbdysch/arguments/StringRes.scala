package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.InvokerConstants._
import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class StringRes() extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith(new StringResImpl(_))
}

private class StringResImpl(val ctx: GenContext) extends ArgDescription with TriviallyDeclared {
  override def typeName: String = "string_t"

  override def requiredTypes(): Seq[ArgDescription] = Seq(this)

  override def requiredLocalVariables(): Seq[AuxRequest] = Nil

  override def globalDeclare(formatter: SourceFormatter): Unit = {}

  override def globalDefine(formatter: SourceFormatter): Unit = {}

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"res_fill_string($InvokerState, $Q$varName$Q, $varName);")
  }

  override protected def valueProcessor: String = "res_process_string"
}
