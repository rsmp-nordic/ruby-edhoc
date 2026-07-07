module Edhoc
  Error = Class.new(StandardError)
end

require_relative "edhoc/version"
require_relative "edhoc/native"
require_relative "edhoc/suite0_session"
