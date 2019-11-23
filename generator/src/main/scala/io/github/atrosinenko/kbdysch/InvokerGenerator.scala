package io.github.atrosinenko.kbdysch

import io.github.atrosinenko.kbdysch.Descriptions.IndexedSyscall
import io.github.atrosinenko.kbdysch.arguments.{AuxRequest, CType}

import scala.collection.mutable
import scala.collection.mutable.ArrayBuffer
import scala.util.control.NonFatal

class InvokerGenerator(descriptions: Descriptions, syscallCapacity: Int, comparisonMode: Boolean) extends SourceFormatter {
  import InvokerConstants._

  private val Q = '"'

  private def generateHeader(): Unit = {
    writeLn(InvokerNotice: _*)
    writeLn(InvokerHeader: _*)
    descriptions.comments.foreach { comment =>
      writeLn(comment.line)
    }
  }

  private def generateEnumUtils(enum: Descriptions.EnumItem): Unit = {
    val opts = enum.options
    if (enum.hasStringType) {
      writeLn(s"$MaybeUnused static const char * ${enum.valueGeneratorName}($InvokerStateArgDeclaration, const char *name) {")
      writeLn(s"  const char *all_opt_values [] = {${opts.mkString(", ")}};")
      writeLn(s"  return invoker_read_string_enum($InvokerState, name, all_opt_values, ${opts.size});")
      writeLn(s"}")
    } else {
      writeLn(s"$MaybeUnused static uint64_t ${enum.valueGeneratorName}($InvokerStateArgDeclaration, const char *name) {")
      writeLn(s"  const uint64_t all_opts_ored    =   ${opts.mkString(" |  ")};")
      writeLn(s"  const uint64_t all_opt_values[] = { ${opts.mkString(" ,  ")}};")
      writeLn(s"  const char *   all_opt_names [] = {$Q${opts.mkString(s"$Q, $Q")}$Q};")
      writeLn(s"  return invoker_read_int_enum($InvokerState, name, all_opts_ored, all_opt_values, all_opt_names, ${opts.size});")
      writeLn(s"}")
    }
  }

  private def generateInvokerWith(name: String)(generateInvokerBody: => Unit): Unit = {
    writeLn(s"static void $name($InvokerStateArgDeclaration) {")
    indented {
      writeLn(s"fprintf(stderr, $Q  Invoker: $name\\n$Q);\n")
      generateInvokerBody
    }
    writeLn(s"}")
  }

  private def forPart(op: => Unit): Unit = {
    if (comparisonMode) {
      writeLn(s"res_save_state($InvokerState);")
      writeLn(s"for (int part = 0; part < res_get_part_count($InvokerState); ++part) {")
      indented {
        writeLn(s"res_restore_state($InvokerState, part);")
        op
      }
      writeLn(s"}")
    } else {
      op
    }
  }

  def generateTypeDeclarations(): Unit = {
    // dedupe, but preserve order of first occurrences
    val knownTypeNames = mutable.Set[String]()
    val types = ArrayBuffer[CType]()
    descriptions.syscalls
      .flatMap { syscall =>
        syscall.allVariables.flatMap { arg =>
          arg.tpe.requiredTypes()
        }
      }
      .foreach { tpe =>
        if (!knownTypeNames.contains(tpe.typeName)) {
          knownTypeNames += tpe.typeName
          types += tpe
        }
      }

    types.foreach { tpe =>
      tpe.globalDeclare(this)
    }
    types.foreach { tpe =>
      tpe.globalDefine(this)
    }
  }

  def generateSyscallInvoker(syscall: IndexedSyscall): Unit = try {
    generateInvokerWith(syscall.invokerName) {
      val auxRequests = syscall.syscall
        .allVariables
        .flatMap { topLevelVar =>
          topLevelVar.tpe.requiredLocalVariables()
        }
      val locals: Seq[AuxRequest] =
        auxRequests ++ syscall.syscall.allVariables.map(x => new AuxRequest(x.tpe))
      val args = syscall.syscall.args

      writeLn("// declare")
      locals.foreach { local =>
        local.declareInstance(this)
      }

      forPart {
        args.foreach { arg =>
          writeLn(s"// initialize: ${arg.name}")
          arg.tpe.initInstance(this)
        }
        writeLn(s"// invoke")
        val (invokeSyscall, argNames) = if (args.nonEmpty)
          ("INVOKE_SYSCALL", ", " + args.map(arg => s"(uint64_t)(${arg.name}[part])").mkString(", "))
        else
          ("INVOKE_SYSCALL_0", "")
        writeLn(s"fprintf(stderr, $Q  Performing ${syscall.syscall.name}... $Q);")
        writeLn(s"${syscall.syscall.ret.tpe.varName} = $invokeSyscall($InvokerState, ${syscall.syscall.name}$argNames);")
        writeLn(s"fprintf(stderr, ${Q}OK\\n${Q});")
        (args :+ syscall.syscall.ret).foreach { arg =>
          writeLn(s"// process return value: ${arg.name}")
          arg.tpe.processReturnValue(this)
        }
        args.foreach { arg =>
          writeLn(s"// deinit: ${arg.name}")
          arg.tpe.deinitInstance(this)
        }
      }
    }
  } catch {
    case NonFatal(ex) =>
      println(s"Error generating invoker for: ${syscall.invokerName}")
      ex.printStackTrace()
      System.exit(1)
  }

  private def generateInvokerDispatcher(descriptions: Descriptions): Unit = {
    assert(descriptions.syscalls.size <= syscallCapacity - 2)

    writeLn(InvokerEntryPoint)
    indented {
      writeLn(s"switch(opc % $syscallCapacity) {")
      indented {
        // emit `case`s for regular invokers
        descriptions.indexedSyscalls.foreach { indexedSyscall =>
          writeLn(s"case ${indexedSyscall.globalIndex}:")
          indented {
            writeLn(s"${indexedSyscall.invokerName}($InvokerState);")
            writeLn(s"break;")
          }
        }
        // emit PATCH
        writeLn(s"case ${syscallCapacity - 2}:")
        indented {
          writeLn(s"kernel_perform_patching($InvokerState);")
          writeLn(s"break;")
        }
        // emit REMOUNT
        writeLn(s"case ${syscallCapacity - 1}:")
        indented {
          writeLn(s"kernel_perform_remount($InvokerState);")
          writeLn(s"break;")
        }
      }
      writeLn("}")
    }
    writeLn(s"}")
  }

  def generate(): String = {
    generateHeader()
    generateTypeDeclarations()
    descriptions.enums.values.foreach { enum =>
      generateEnumUtils(enum)
    }
    descriptions.indexedSyscalls.foreach { indexedSyscall =>
      generateSyscallInvoker(indexedSyscall)
    }
    generateInvokerDispatcher(descriptions)

    getResult
  }
}
