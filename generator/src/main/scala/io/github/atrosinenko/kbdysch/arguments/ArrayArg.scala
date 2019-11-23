package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.InvokerConstants._
import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

final case class ArrayArg(tpe: ArgDescriptionConstructor, size: IntegerRange = IntegerRange(1, 20)) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = ctx.createWith { thisCtx =>
    val indexedCtx = thisCtx.spawnIndexed(size.max, thisCtx.indexesWith)
    new ArrayImpl(
      tpe.instantiate(descriptions, indexedCtx),
      size,
      thisCtx,
    )
  }
}

private class ArrayImpl(tpe: ArgDescription, size: IntegerRange, val ctx: GenContext) extends ArgDescription with ArgWithLength {
  private val elementCount = new AuxRequest(
    new IntegerImpl(64, signed = false, size, ctx.spawnAux("element_count"))
  )

  private val deepLocals = tpe.requiredLocalVariables()

  override def typeName: String = s"${tpe.typeName}_array_${size.max}"

  override def globalDeclare(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"typedef ${tpe.typeName} $typeName[${size.max}];")
  }

  override def globalDefine(formatter: SourceFormatter): Unit = {}

  override def requiredTypes(): Seq[CType] = tpe.requiredTypes() ++ deepLocals.map(_.cType) :+ this

  override def requiredLocalVariables(): Seq[AuxRequest] = {
    val ownLocals = Seq(elementCount)
    deepLocals ++ ownLocals
  }


  override def lengthVarName: String = elementCount.varName

  override def requiresStatic: Boolean = true

  private def iterations(formatter: SourceFormatter)(op: => Unit): Unit = {
    val countName = elementCount.varName
    val indexName = ctx.indexesWith
    formatter.writeLn(s"for (int $indexName = 0; $indexName < $countName; ++$indexName) {")
    formatter.indented {
      op
    }
    formatter.writeLn("}")
  }

  override def initInstance(formatter: SourceFormatter): Unit = {
    if (size.min == size.max) {
      formatter.writeLn(s"${elementCount.varName} = ${size.min};")
    } else {
      formatter.writeLn(s"${elementCount.varName} = res_decide_array_size($InvokerState, $Q$varName$Q, ${size.min}, ${size.max});")
    }
    iterations(formatter) {
      tpe.initInstance(formatter)
    }
  }

  override def deinitInstance(formatter: SourceFormatter): Unit = {
    iterations(formatter) {
      tpe.deinitInstance(formatter)
    }
  }

  override def processReturnValue(formatter: SourceFormatter): Unit = {
    iterations(formatter) {
      tpe.processReturnValue(formatter)
    }
  }
}
