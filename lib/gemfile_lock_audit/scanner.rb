# frozen_string_literal: true

require_relative "parser"
require_relative "rules"

module GemfileLockAudit
  Report = Struct.new(:path, :findings, :score, :grade, keyword_init: true)

  module Scanner
    module_function

    def score_to_grade(score)
      case score
      when 90..Float::INFINITY then "A"
      when 75...90 then "B"
      when 60...75 then "C"
      when 40...60 then "D"
      else "F"
      end
    end

    def scan_text(text, path: "Gemfile.lock")
      lockfile = Parser.parse(text)
      findings = Rules::ALL.flat_map { |rule| Rules.public_send(rule, lockfile) }

      score = 100
      findings.each { |f| score -= SEVERITY_WEIGHTS.fetch(f.severity) }
      score = score.clamp(0, 100)

      Report.new(path: path, findings: findings, score: score, grade: score_to_grade(score))
    end

    def scan_file(path)
      text = File.read(path)
      scan_text(text, path: path)
    rescue Errno::ENOENT
      raise ParseError, "no such file: #{path}"
    end
  end
end
