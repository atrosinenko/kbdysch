package io.github.atrosinenko.kbdysch

import scala.collection.mutable

trait SourceFormatter {
  private val result = new mutable.StringBuilder()
  private var _indentation: String = ""
  private var _level = 0

  def indented(op: => Unit): Unit = {
    val oldIndentation = _indentation
    try {
      _indentation = _indentation + "  "
      _level += 1
      op
    } finally {
      _indentation = oldIndentation
      _level -= 1
    }
  }

  def level: Int = _level

  def writeLn(lines: String*): Unit = {
    lines.foreach { line =>
      result.append(_indentation)
      result.append(line)
      result.append('\n')
    }
  }

  protected def getResult: String = result.toString()
}
