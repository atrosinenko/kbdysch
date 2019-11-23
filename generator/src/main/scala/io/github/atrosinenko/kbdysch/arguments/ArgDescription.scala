package io.github.atrosinenko.kbdysch.arguments

import io.github.atrosinenko.kbdysch.InvokerConstants._
import io.github.atrosinenko.kbdysch.SourceFormatter

abstract class ArgDescription extends CType {
  def ctx: GenContext

  final def varName: String = ctx.fullVarName(isPart0 = false)
  final def refVarName: String = ctx.fullVarName(isPart0 = true)
  final def declaredName: String = ctx.fullDeclaredName

  def requiresStatic: Boolean = false

  def sizeof: String = s"sizeof($varName)"

  /**
   * Collect contained types.
   */
  def requiredTypes(): Seq[CType]

  /**
   * What auxiliary variables would `this` require during its operations.
   */
  def requiredLocalVariables(): Seq[AuxRequest]

  /**
   * Declares local variable. Aux variables are declared automatically.
   */
  final def declareInstance(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"${if (requiresStatic) "static " else ""}$typeName $declaredName;")
  }

  /**
   * Initializes local variable and aux locals.
   */
  def initInstance(formatter: SourceFormatter): Unit

  /**
   * Frees resources consumed by a local variable and aux locals.
   */
  def deinitInstance(formatter: SourceFormatter): Unit

  protected def valueProcessor: String = ???

  /**
   * Processes a value returned by the kernel, including aux locals.
   */
  def processReturnValue(formatter: SourceFormatter): Unit = {
    formatter.writeLn(s"$valueProcessor($InvokerState, $Q$varName$Q, $refVarName, $varName);")
  }
}
