package io.github.atrosinenko.kbdysch

import java.io.File
import java.nio.file.{Files, Paths}

object InvokerUpdater {
  import InvokerConstants._

  private final case class Operation(sourceFile: String, destinationFile: String)

  private def printHelpAndExitIfNeeded(args: Array[String]): Unit = {
    if (args.isEmpty) {
      println("Arguments: input-description:output-invoker ...")
    }
  }

  private def parseArgs(args: Array[String]): Seq[Operation] = {
    args.map { arg =>
      val separatorIndex = arg.indexOf(':')
      if (separatorIndex == -1) {
        println(s"Error: an argument '$arg' does not contain the ':' separator.")
        System.exit(1)
      }
      val input = arg.substring(0, separatorIndex)
      val output = arg.substring(separatorIndex + 1)
      Operation(input, output)
    }
  }

  private def parseInput(sourceFile: File): Descriptions = {
    if (!sourceFile.exists()) {
      println(s"Error: source file '${sourceFile.getAbsoluteFile}' does not exist.")
      System.exit(1)
    }
    val descriptions = SyzkallerDescriptionParser.parse(sourceFile)
    if (descriptions.isLeft) {
      println(s"Error while parsing ${sourceFile.toString}: ${descriptions.left.get}")
      System.exit(1)
    }
    descriptions.right.get
  }

  def main(args: Array[String]): Unit = {
    val sourceDirectory = Paths.get(SyscallDescriptionDirectory)
    val destinationDirectory = Paths.get(GeneratedInvokerDirectory)

    printHelpAndExitIfNeeded(args)

    destinationDirectory.toFile.mkdir()

    parseArgs(args).foreach { operation =>
      val descriptions = parseInput(sourceDirectory.resolve(operation.sourceFile).toFile)

      // Use several lowest bits of opcode for determining what to call
      val syscallCount = descriptions.indexedSyscalls.size
      val syscallCapacity = 1 << (Math.log(syscallCount + 2) / Math.log(2)).ceil.toInt

      val destinationPath = destinationDirectory.resolve(operation.destinationFile)
      println(s"Generating ${destinationPath.toString} with syscall count = $syscallCount, capacity = $syscallCapacity...")
      val invokerAsString = new InvokerGenerator(descriptions, syscallCapacity, true).generate()
      Files.write(destinationPath, invokerAsString.getBytes)
    }
  }
}
