require_relative 'test_helper'

describe 'README examples' do
  it 'keeps every Ruby example syntactically valid' do
    readme = File.read(File.expand_path('../README.md', __dir__), encoding: 'UTF-8')
    examples = readme.scan(/```ruby\n(.*?)```/m).flatten
    expect(examples.empty?).to be == false

    examples.each_with_index do |source, index|
      RubyVM::InstructionSequence.compile(source, "README example #{index + 1}")
    end
  end
end
