package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.Descriptions

final case class UnknownArg(parsed: AnyRef) extends ArgDescriptionConstructor {
  override def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription = {
    throw new IllegalArgumentException(s"Unknown type: $parsed")
  }
}
