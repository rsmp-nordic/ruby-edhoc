module EdhocNative
  # Selects a CMake toolchain compatible with Ruby's native extension compiler.
  class BuildConfig
    MINGW_GENERATOR = 'MSYS Makefiles'.freeze

    attr_reader :generator, :compiler

    def initialize(platform: RUBY_PLATFORM, environment: ENV)
      configured_generator = environment['CMAKE_GENERATOR']
      @generator = configured_generator unless configured_generator.to_s.empty?
      return unless platform.include?('mingw') && !@generator

      @generator = MINGW_GENERATOR
      configured_compiler = environment['CC']
      @compiler = configured_compiler.to_s.empty? ? 'gcc' : configured_compiler
    end

    def cmake_arguments
      arguments = []
      arguments.push('-G', generator) if generator
      arguments << "-DCMAKE_C_COMPILER=#{compiler}" if compiler
      arguments
    end
  end
end
