package io.github.atrosinenko.kbdysch

package object arguments {
  trait ArgDescriptionConstructor {
    def instantiate(descriptions: Descriptions, ctx: GenContext): ArgDescription
  }

  class AuxRequest(private var _tpe: ArgDescription) {
    def varName: String = _tpe.varName
    def refVarName: String = _tpe.refVarName
    def declareInstance(formatter: SourceFormatter): Unit = _tpe.declareInstance(formatter)
    def replace(op: ArgDescription => ArgDescription): Unit = {
      _tpe = op(_tpe)
    }
    def cType: CType = _tpe
  }

  trait PrimitiveTypedArg { self: ArgDescription =>
    override def requiredTypes(): Seq[ArgDescription] = Nil
    override def requiredLocalVariables(): Seq[AuxRequest] = Nil
    override def globalDeclare(formatter: SourceFormatter): Unit = {}
    override def globalDefine(formatter: SourceFormatter): Unit = {}
  }

  trait TriviallyDeclared { self: ArgDescription =>
    override def deinitInstance(formatter: SourceFormatter): Unit = {}
  }

  trait ArgWithLength { self: ArgDescription =>
    def lengthVarName: String
  }

  trait CType {
    /**
     * Used to deduplicate collected type declarations for the purpose of global declarations.
     */
    def typeName: String

    /**
     * Emits a forward declaration in a global scope.
     */
    def globalDeclare(formatter: SourceFormatter): Unit

    /**
     * Emits type definition in a global scope.
     */
    def globalDefine(formatter: SourceFormatter): Unit
  }

  object IntegerRange {
    val any = IntegerRange(0, 0)
    val anyPositive = IntegerRange(0, 1 << 30)
  }
  final case class IntegerRange(min: Int, max: Int)

  sealed abstract class Direction(val cName: String)
  case object Inherit extends Direction("???")
  case object In extends Direction("IN")
  case object Out extends Direction("OUT")
  case object InOut extends Direction("INOUT")
}
