package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.Descriptions

final case class Ref(typeName: String) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = {
    val structLike = descriptions.structs(typeName)
    StructLikeImpl.instantiate(descriptions, ctx, structLike)
  }
}
