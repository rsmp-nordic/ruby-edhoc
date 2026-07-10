require_relative '../ext/edhoc_native/build_config'

describe EdhocNative::BuildConfig do
  it 'uses MSYS Makefiles and GCC for mingw Ruby' do
    config = EdhocNative::BuildConfig.new(platform: 'x64-mingw-ucrt', environment: {})

    expect(config.cmake_arguments).to be == [
      '-G',
      'MSYS Makefiles',
      '-DCMAKE_C_COMPILER=gcc'
    ]
  end

  it 'uses the configured C compiler with the default mingw generator' do
    config = EdhocNative::BuildConfig.new(
      platform: 'x64-mingw-ucrt',
      environment: { 'CC' => 'clang' }
    )

    expect(config.cmake_arguments).to be == [
      '-G',
      'MSYS Makefiles',
      '-DCMAKE_C_COMPILER=clang'
    ]
  end

  it 'preserves an explicitly configured CMake generator' do
    config = EdhocNative::BuildConfig.new(
      platform: 'x64-mingw-ucrt',
      environment: { 'CMAKE_GENERATOR' => 'Ninja' }
    )

    expect(config.cmake_arguments).to be == ['-G', 'Ninja']
  end

  it 'does not select a generator on non-Windows platforms' do
    config = EdhocNative::BuildConfig.new(platform: 'arm64-darwin', environment: {})

    expect(config.cmake_arguments).to be == []
  end
end
