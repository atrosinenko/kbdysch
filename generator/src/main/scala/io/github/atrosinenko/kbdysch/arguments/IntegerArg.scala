package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.InvokerConstants._
import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class IntegerArg(bitWidth: Int, signed: Boolean, range: IntegerRange = IntegerRange.any) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith(new IntegerImpl(bitWidth, signed, range, _))
}

private class IntegerImpl(bitWidth: Int, signed: Boolean, range: IntegerRange, val ctx: GenContext) extends ArgDescription with PrimitiveTypedArg with TriviallyDeclared {
  override def typeName: String = {
    val unsignedPrefix = if (signed) "" else "u"
    val widthInfix = bitWidth.toInt
    s"${unsignedPrefix}int${widthInfix}_t"
  }

  override def initInstance(formatter: SourceFormatter): Unit = {
    if (range == IntegerRange.any) {
      formatter.writeLn(s"$varName = res_get_named_uint($InvokerState, $Q$varName$Q, ${bitWidth / 8});")
    } else {
      formatter.writeLn(s"$varName = res_get_integer_from_range(state, $Q$varName$Q, ${range.min}, ${range.max});")
    }
  }

  override protected def valueProcessor: String = "res_process_integer"
}
