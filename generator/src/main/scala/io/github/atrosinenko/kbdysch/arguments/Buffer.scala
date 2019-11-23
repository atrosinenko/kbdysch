package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.InvokerConstants._
import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class Buffer(direction: Direction) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription =
    ctx.setDirection(direction).createWith { thisCtx =>
      new BufferImpl(thisCtx)
    }
}

private class BufferImpl(val ctx: GenContext) extends ArgDescription with TriviallyDeclared with ArgWithLength {
  val lengthVariable = new AuxRequest(new IntegerImpl(64, false, IntegerRange.anyPositive, ctx.spawnAux("length")))

  override def lengthVarName: String = lengthVariable.varName

  override def typeName: String = "buffer_t"

  override def requiresStatic: Boolean = true

  override def requiredLocalVariables(): Seq[AuxRequest] = Seq(lengthVariable)

  override def requiredTypes(): Seq[ArgDescription] = Seq(this)
  override def globalDeclare(formatter: SourceFormatter): Unit = {}
  override def globalDefine(formatter: SourceFormatter): Unit = {}

  override def initInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"res_fill_buffer($InvokerState, $Q$varName$Q, $varName, &${lengthVariable.varName}, ${ctx.direction.cName});")
  }

  override def processReturnValue(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"res_process_buffer($InvokerState, $Q$varName$Q, $refVarName, ${lengthVariable.refVarName}, $varName, ${lengthVariable.varName}, ${ctx.direction.cName});")
  }
}