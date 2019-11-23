package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.Descriptions.StructLike
import io.github.atrosinenko.kbdysch.{Descriptions, SourceFormatter}

object StructLikeImpl {
  def instantiate(descriptions: Descriptions, ctx: GenContext, structOrUnion: StructLike): ArgDescription = ctx.createWith { thisCtx =>
    val fieldImpls = structOrUnion.fields.map { field =>
      field.tpe.instantiate(descriptions, thisCtx.spawnNested(field.name))
    }
    new StructLikeImpl(structOrUnion.name, fieldImpls, structOrUnion.isUnion, thisCtx)
  }
}

private class StructLikeImpl(name: String, fields: Seq[ArgDescription], isUnion: Boolean, val ctx: GenContext) extends ArgDescription {
  private val kind = if (isUnion) "union" else "struct"

  override def typeName: String = s"${name}_t"

  override def requiredTypes(): Seq[CType] = this +: fields.flatMap { field =>
    field.requiredTypes()
  }

  override def requiredLocalVariables(): Seq[AuxRequest] = fields.flatMap { field =>
    field.requiredLocalVariables()
  }

  override def globalDeclare(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"typedef $kind $name $typeName;")
  }

  override def globalDefine(formatter: SourceFormatter): Unit = {}

  override def initInstance(formatter: SourceFormatter): Unit = fields.foreach { field =>
    field.initInstance(formatter)
  }

  override def deinitInstance(formatter: SourceFormatter): Unit = fields.foreach { field =>
    field.deinitInstance(formatter)
  }

  override def processReturnValue(formatter: SourceFormatter): Unit = fields.foreach { field =>
    field.processReturnValue(formatter)
  }
}